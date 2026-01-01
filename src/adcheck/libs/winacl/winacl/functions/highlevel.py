import ctypes
from winacl.functions.constants import SE_OBJECT_TYPE
from winacl.functions.kernel32 import CloseHandle, CreateFileW, GENERIC_READ, READ_CONTROL, OPEN_EXISTING, FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS
from winacl.functions.advapi32 import LookupAccountNameW, LookupAccountSidW, \
	GetSecurityInfo, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, \
	DACL_SECURITY_INFORMATION, OpenSCManagerW, SC_MANAGER_ENUMERATE_SERVICE, \
	EnumServicesStatusW, OpenServiceW, QueryServiceObjectSecurity, CloseServiceHandle, \
	hive_name_map, RegOpenKeyExW, RegCloseKey, RegEnumKeyExW, RegEnumValueW, \
	SetSecurityInfo, BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, \
	ConvertSidToStringSidW, ConvertStringSidToSidW, \
	ConvertSecurityDescriptorToStringSecurityDescriptorW, OpenProcessToken, GetTokenInformation, \
	LsaGetLogonSessionData, TokenStatistics, OpenProcess, GetCurrentProcessId
from winacl.functions.netapi32 import NetUserGetLocalGroups, NetUserGetInfo
import glob
import os
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.ace import ACCESS_ALLOWED_ACE, AceFlags, FILE_ACCESS_MASK, ACCESS_MASK
from winacl.dtyp.sid import SID
from winacl.functions.rights_calc import EvaluateSidAgainstDescriptor

def get_sid_for_user(username):
	sid, domain, use = LookupAccountNameW(None, username)
	return sid

def get_user_for_sid(sid_str):
	sid = SID.from_string(sid_str)
	username, domain, use = LookupAccountSidW(None, sid.to_bytes())
	return '%s\\%s' % (domain, username)

def get_reg_sd(key_handle):
	sd = GetSecurityInfo(key_handle, SE_OBJECT_TYPE.SE_REGISTRY_KEY.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	return sd

def set_file_sd(file_path, sd):
	req_rights = 0x10000000	#GENERIC_ALL
	file_handle = CreateFileW(file_path, dwDesiredAccess = req_rights, dwCreationDisposition = OPEN_EXISTING)
	SetSecurityInfo(file_handle, SE_OBJECT_TYPE.SE_FILE_OBJECT.value, sd)
	CloseHandle(file_handle)

def get_file_sd(file_path):
	file_handle = CreateFileW(file_path, dwDesiredAccess = READ_CONTROL, dwCreationDisposition = OPEN_EXISTING)
	sd = GetSecurityInfo(file_handle, SE_OBJECT_TYPE.SE_FILE_OBJECT.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	CloseHandle(file_handle)
	return sd

def get_directory_sd(dir_path):
	file_handle = CreateFileW(dir_path, dwDesiredAccess = READ_CONTROL, dwCreationDisposition = OPEN_EXISTING, dwFlagsAndAttributes = FILE_ATTRIBUTE_DIRECTORY | FILE_FLAG_BACKUP_SEMANTICS)
	sd = GetSecurityInfo(file_handle, SE_OBJECT_TYPE.SE_FILE_OBJECT.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	CloseHandle(file_handle)
	return sd

def get_dir_file_recursive(dir_path, with_files = False):
	if dir_path[-1] != '\\':
		dir_path += '\\'
	for filename in glob.iglob(dir_path + '**/*', recursive=True):
		if os.path.isdir(filename) is True:
			try:
				yield filename, 'dir', get_directory_sd(filename)
			except:
				yield filename, 'dir', 'ERR'
		elif with_files is True and os.path.isfile(filename) is True:
			try:
				yield filename, 'file', get_file_sd(filename)
			except:
				yield filename, 'file', 'ERR'

def get_servicemanager_sd():
	scm_handle = OpenSCManagerW(dwDesiredAccess = READ_CONTROL )
	sd = QueryServiceObjectSecurity(scm_handle, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd_object_type = SE_OBJECT_TYPE.SE_SERVICE)
	CloseServiceHandle(scm_handle)
	return sd

def get_service_sd(service_name):
	scm_handle = OpenSCManagerW(dwDesiredAccess = READ_CONTROL | SC_MANAGER_ENUMERATE_SERVICE )
	service_handle = OpenServiceW(scm_handle, service_name, dwDesiredAccess = READ_CONTROL)
	sd = QueryServiceObjectSecurity(service_handle, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd_object_type = SE_OBJECT_TYPE.SE_SERVICE)
	CloseServiceHandle(scm_handle)
	CloseServiceHandle(service_handle)
	return sd

def enumerate_all_service_sd():
	yield 'SCM', get_servicemanager_sd()
	scm_handle = OpenSCManagerW(dwDesiredAccess = READ_CONTROL | SC_MANAGER_ENUMERATE_SERVICE )
	for service_name in EnumServicesStatusW(scm_handle):
		try:
			service_handle = OpenServiceW(scm_handle, service_name, dwDesiredAccess = READ_CONTROL)
			sd = QueryServiceObjectSecurity(service_handle, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd_object_type = SE_OBJECT_TYPE.SE_SERVICE)
			yield service_name, sd
		except Exception as e:
			yield service_name, 'err'
		finally:
			try:
				CloseServiceHandle(service_handle)
			except:
				pass
	try:
		CloseServiceHandle(scm_handle)
	except:
		pass

def get_registry_hive_sd(hive_name):
	key_handle = hive_name_map[hive_name]
	sd = GetSecurityInfo(key_handle, SE_OBJECT_TYPE.SE_REGISTRY_KEY.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	return sd

def get_registry_key_sd(reg_path):
	# eg. HKLM\\SAM
	path_elements = reg_path.split('\\')
	reg_handle = hive_name_map[path_elements[0]]
	handles = []
	for name in path_elements[1:-1]:
		reg_handle = RegOpenKeyExW(reg_handle, name)
		handles.append(reg_handle)
	
	sd = GetSecurityInfo(reg_handle, SE_OBJECT_TYPE.SE_REGISTRY_KEY.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	for reg_handle in handles[::-1]:
		RegCloseKey(reg_handle)
	
	return sd

#def get_maximum_permissions_for_sid(sd, sid):
#	EvaluateSidAgainstDescriptor

def get_maximum_permissions_for_user(sd, username):
	sid_groups = []
	domain = None
	if username.find('\\') != -1:
		domain, username = username.split('\\')

	user_sid, *t = LookupAccountNameW(domain, username)
	#print(str(user_sid))
	sid_groups.append(user_sid)
	for group_name in NetUserGetLocalGroups(domain, username):
		#print(group_name)
		sid, groupname, use = LookupAccountNameW(domain, group_name)
		#print(str(sid))
		sid_groups.append(sid)
	#print(win32net.NetUserGetLocalGroups('TEST', 'victim'))
	#input([str(x) for x in sid_groups])
	res, mask = EvaluateSidAgainstDescriptor(sd, user_sid, 0x02000000, sid_groups)
	return mask

def enumerate_registry_sd(reg_path, reg_handle = None):
	# TODO: do this
	if reg_path[-1] == '\\':
		reg_path = reg_path[:-1]
	handles = []
	if reg_handle is None:
		path_elements = reg_path.split('\\')
		reg_handle = hive_name_map[path_elements[0]]
		handles = []
		for name in path_elements[1:]:
			reg_handle = RegOpenKeyExW(reg_handle, name)
			handles.append(reg_handle)

	subkeys = RegEnumKeyExW(reg_handle)
	#print(subkeys)
	for sk in subkeys:
		reg_path_sk = '%s\\%s' % (reg_path, sk)
		#print(reg_path_sk)
		try:
			reg_handle_sk = RegOpenKeyExW(reg_handle, sk)
		except Exception as e:
			if str(e).find('cannot find') != -1:
				print(str(e) + reg_path_sk)
			else:
				print(e)
			
		else:
			sd = GetSecurityInfo(reg_handle, SE_OBJECT_TYPE.SE_REGISTRY_KEY.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, se_object_type = SE_OBJECT_TYPE.SE_REGISTRY_KEY)
			yield (reg_path_sk, sd)
			yield from enumerate_registry_sd(reg_path_sk, reg_handle_sk)

	for reg_handle in handles:
		RegCloseKey(reg_handle)

def get_logon_info():
	phandle = OpenProcess(None , False, GetCurrentProcessId())
	tokhandle = OpenProcessToken(phandle)
	stats = GetTokenInformation(tokhandle, TokenStatistics)
	return LsaGetLogonSessionData(stats.AuthenticationId)
