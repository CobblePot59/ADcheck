import enum
from winacl.functions.defines import *
from winacl.functions.kernel32 import GetLastError, LocalFree, READ_CONTROL
from winacl.functions.membuff import MemoryBuffer
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.sid import SID
from winacl.functions.constants import SE_OBJECT_TYPE

def win_succ_check(result, func, arguments):
	if result != 0:
		raise ctypes.WinError(result)
	return result

### https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/advapi32.py
### most parts taken from here!

TOKEN_INFORMATION_CLASS = ctypes.c_int

TokenUser                               = 1
TokenGroups                             = 2
TokenPrivileges                         = 3
TokenOwner                              = 4
TokenPrimaryGroup                       = 5
TokenDefaultDacl                        = 6
TokenSource                             = 7
TokenType                               = 8
TokenImpersonationLevel                 = 9
TokenStatistics                         = 10
TokenRestrictedSids                     = 11
TokenSessionId                          = 12
TokenGroupsAndPrivileges                = 13
TokenSessionReference                   = 14
TokenSandBoxInert                       = 15
TokenAuditPolicy                        = 16
TokenOrigin                             = 17
TokenElevationType                      = 18
TokenLinkedToken                        = 19
TokenElevation                          = 20
TokenHasRestrictions                    = 21
TokenAccessInformation                  = 22
TokenVirtualizationAllowed              = 23
TokenVirtualizationEnabled              = 24
TokenIntegrityLevel                     = 25
TokenUIAccess                           = 26
TokenMandatoryPolicy                    = 27
TokenLogonSid                           = 28
TokenIsAppContainer                     = 29
TokenCapabilities                       = 30
TokenAppContainerSid                    = 31
TokenAppContainerNumber                 = 32
TokenUserClaimAttributes                = 33
TokenDeviceClaimAttributes              = 34
TokenRestrictedUserClaimAttributes      = 35
TokenRestrictedDeviceClaimAttributes    = 36
TokenDeviceGroups                       = 37
TokenRestrictedDeviceGroups             = 38
TokenSecurityAttributes                 = 39
TokenIsRestricted                       = 40
MaxTokenInfoClass                       = 41

# Token access rights
TOKEN_ASSIGN_PRIMARY    = 0x0001
TOKEN_DUPLICATE         = 0x0002
TOKEN_IMPERSONATE       = 0x0004
TOKEN_QUERY             = 0x0008
TOKEN_QUERY_SOURCE      = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS     = 0x0040
TOKEN_ADJUST_DEFAULT    = 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343
OWNER_SECURITY_INFORMATION = 0x00000001 #The owner identifier of the object is being referenced.
GROUP_SECURITY_INFORMATION = 0x00000002 #The primary group identifier of the object is being referenced.
DACL_SECURITY_INFORMATION = 0x00000004 #The DACL of the object is being referenced.
SACL_SECURITY_INFORMATION = 0x00000008 #The SACL of the object is being referenced.
LABEL_SECURITY_INFORMATION = 0x00000010 #The mandatory integrity label is being referenced.
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000 #The SACL inherits access control entries (ACEs) from the parent object.
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000 #The DACL inherits ACEs from the parent object.
PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000 #The SACL cannot inherit ACEs.
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000 #The DACL cannot inherit ACEs.
ATTRIBUTE_SECURITY_INFORMATION = 0x00000020 #A SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15) is being referenced.
SCOPE_SECURITY_INFORMATION = 0x00000040 #A SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16) is being referenced.
PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080 #Reserved.
BACKUP_SECURITY_INFORMATION = 0x00010000 #The security descriptor is being accessed for use in a backup operation.


# EnumServicesStatusEx() service type filters (in addition to actual types)
SERVICE_DRIVER = 0x0000000B # SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER
SERVICE_WIN32  = 0x00000030 # SERVICE_WIN32_OWN_PROCESS and SERVICE_WIN32_SHARE_PROCESS

# EnumServicesStatusEx() service state filters
SERVICE_ACTIVE    = 1
SERVICE_INACTIVE  = 2
SERVICE_STATE_ALL = 3


SC_HANDLE = HANDLE

SERVICE_ALL_ACCESS           = 0xF01FF
SERVICE_QUERY_CONFIG         = 0x0001
SERVICE_CHANGE_CONFIG        = 0x0002
SERVICE_QUERY_STATUS         = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_START                = 0x0010
SERVICE_STOP                 = 0x0020
SERVICE_PAUSE_CONTINUE       = 0x0040
SERVICE_INTERROGATE          = 0x0080
SERVICE_USER_DEFINED_CONTROL = 0x0100

SC_MANAGER_ALL_ACCESS           = 0xF003F
SC_MANAGER_CONNECT              = 0x0001
SC_MANAGER_CREATE_SERVICE       = 0x0002
SC_MANAGER_ENUMERATE_SERVICE    = 0x0004
SC_MANAGER_LOCK                 = 0x0008
SC_MANAGER_QUERY_LOCK_STATUS    = 0x0010
SC_MANAGER_MODIFY_BOOT_CONFIG   = 0x0020



# https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo

#DWORD SetSecurityInfo(
#  HANDLE               handle,
#  SE_OBJECT_TYPE       ObjectType,
#  SECURITY_INFORMATION SecurityInfo,
#  PSID                 psidOwner,
#  PSID                 psidGroup,
#  PACL                 pDacl,
#  PACL                 pSacl
#);


def SetSecurityInfo(handle_obj, obj_type, sd):
	#Warning  If the supplied handle was opened with an ACCESS_MASK value of MAXIMUM_ALLOWED, then the SetSecurityInfo function will not propagate ACEs to children.

	_SetSecurityInfo = windll.advapi32.SetSecurityInfo
	_SetSecurityInfo.argtypes = [HANDLE, DWORD, DWORD, PVOID, PVOID, PVOID, PVOID]
	_SetSecurityInfo.restype  = DWORD
	_SetSecurityInfo.errcheck = RaiseIfNotErrorSuccess

	sec_info = 0
	pOwner = None
	if sd.Owner is not None:
		sec_info |= OWNER_SECURITY_INFORMATION
		owner_data = sd.Owner.to_bytes()
		pOwner = ctypes.create_string_buffer(owner_data, len(owner_data))
	
	pGroup = None
	#if sd.Group is not None:
	#	sec_info |= GROUP_SECURITY_INFORMATION
	#	group_data = sd.Group.to_bytes()
	#	pGroup = ctypes.create_string_buffer(group_data, len(group_data))
	
	pDacl = None
	if sd.Dacl is not None:
		sec_info |= DACL_SECURITY_INFORMATION
		dacl_data = sd.Dacl.to_bytes()
		pDacl = ctypes.create_string_buffer(dacl_data, len(dacl_data))
	
	pSacl = None
	#if sd.Sacl is not None:
	#	sec_info |= SACL_SECURITY_INFORMATION
	#	sacl_data = sd.Sacl.to_bytes()
	#	pSacl = ctypes.create_string_buffer(sacl_data, len(sacl_data))

	if sec_info == 0:
		raise Exception('Looks like nothing is to be set! Check your sd object!')

	#print(sec_info)
	ret = _SetSecurityInfo(
		handle_obj, 
		obj_type, 
		sec_info, 
		pOwner, 
		pGroup, 
		pDacl, 
		pSacl
	)




# https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo

# DWORD GetSecurityInfo(
#  HANDLE               handle,
#  SE_OBJECT_TYPE       ObjectType,
#  SECURITY_INFORMATION SecurityInfo,
#  PSID                 *ppsidOwner,
#  PSID                 *ppsidGroup,
#  PACL                 *ppDacl,
#  PACL                 *ppSacl,
#  PSECURITY_DESCRIPTOR *ppSecurityDescriptor
#);

def GetSecurityInfo(handle_obj, obj_type, info_req):
	_GetSecurityInfo = windll.advapi32.GetSecurityInfo
	_GetSecurityInfo.argtypes = [HANDLE, DWORD, DWORD, PVOID, PVOID, PVOID, PVOID, PVOID] #[HANDLE, SE_OBJECT_TYPE, DWORD, PSID, PSID, PACL, PACL, PSECURITY_DESCRIPTOR]
	_GetSecurityInfo.restype  = DWORD
	_GetSecurityInfo.errcheck = win_succ_check

	ppsidOwner = None
	ppsidGroup = None
	ppDacl = None
	ppSacl = None
	ppSecurityDescriptor = ctypes.pointer(ctypes.c_uint(0))

	ret = _GetSecurityInfo(handle_obj, obj_type, info_req, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ctypes.byref(ppSecurityDescriptor))
	pSecurityDescriptor = ppSecurityDescriptor.contents
	buff = MemoryBuffer(ctypes.addressof(ppSecurityDescriptor.contents))	
	sd = SECURITY_DESCRIPTOR.from_buffer(buff, obj_type)
	LocalFree(ppSecurityDescriptor)
	return sd


# https://docs.microsoft.com/en-us/windows/win32/api/accctrl/ns-accctrl-trustee_w
class TRUSTEE_W(Structure):
	_fields_ = [
		("pMultipleTrustee", PVOID),
		("MultipleTrusteeOperation", DWORD),
		("TrusteeForm", DWORD),
		("TrusteeType", DWORD),
		("ptstrName", HANDLE),
	]
PTRUSTEE_W = ctypes.POINTER(TRUSTEE_W)


# https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-buildtrusteewithsidw
#void BuildTrusteeWithSidW(
#  PTRUSTEE_W pTrustee,
#  PSID       pSid
#);

def BuildTrusteeWithSidW(sid):
	_BuildTrusteeWithSidW = windll.advapi32.BuildTrusteeWithSidW
	_BuildTrusteeWithSidW.argtypes = [PTRUSTEE_W, PVOID] #[HANDLE, SE_OBJECT_TYPE, DWORD, PSID, PSID, PACL, PACL, PSECURITY_DESCRIPTOR]
	_BuildTrusteeWithSidW.restype  = None

	sid_data = sid.to_bytes()
	csid = ctypes.create_string_buffer(sid_data, len(sid_data))

	trustee = TRUSTEE_W()

	_BuildTrusteeWithSidW(trustee, csid)
	return trustee

# https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsidw

#BOOL ConvertSidToStringSidW(
#  PSID   Sid,
#  LPWSTR *StringSid
#);

def ConvertSidToStringSidW(sid, is_raw_ptr = False):
	_ConvertSidToStringSidW = windll.advapi32.ConvertSidToStringSidW
	_ConvertSidToStringSidW.argtypes = [PVOID, PVOID] #[HANDLE, SE_OBJECT_TYPE, DWORD, PSID, PSID, PACL, PACL, PSECURITY_DESCRIPTOR]
	_ConvertSidToStringSidW.restype  = DWORD
	_ConvertSidToStringSidW.errcheck = RaiseIfZero

	if is_raw_ptr is False:
		sid_data = sid.to_bytes()
		csid = ctypes.create_string_buffer(sid_data, len(sid_data))
		pstr = ctypes.create_unicode_buffer(1) #size is irrelevant here
		cstr_sid = ctypes.pointer(pstr)
	
		_ConvertSidToStringSidW(byref(csid), byref(cstr_sid))
	else:
		pstr = ctypes.create_unicode_buffer(1) #size is irrelevant here
		cstr_sid = ctypes.pointer(pstr)
	
		_ConvertSidToStringSidW(sid, byref(cstr_sid))

	str_sid = ctypes.wstring_at(cstr_sid)
	LocalFree(cstr_sid)

	return str_sid

# https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsidtosidw

#BOOL ConvertStringSidToSidW(
#  LPCWSTR StringSid,
#  PSID   *Sid
#);
def ConvertStringSidToSidW(sid_str):
	_ConvertStringSidToSidW = windll.advapi32.ConvertStringSidToSidW
	_ConvertStringSidToSidW.argtypes = [PVOID, PVOID] #[HANDLE, SE_OBJECT_TYPE, DWORD, PSID, PSID, PACL, PACL, PSECURITY_DESCRIPTOR]
	_ConvertStringSidToSidW.restype  = DWORD
	_ConvertStringSidToSidW.errcheck = RaiseIfZero

	

	cstr_sid = ctypes.create_string_buffer(sid_str.encode('utf-16-le'))
	ppSecurityDescriptor = ctypes.pointer(ctypes.c_uint(0))
	
	_ConvertStringSidToSidW(cstr_sid, byref(ppSecurityDescriptor))
	buff = MemoryBuffer(ctypes.addressof(ppSecurityDescriptor.contents))
	sd = SID.from_buffer(buff)
	LocalFree(ppSecurityDescriptor)
	return sd

# https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-geteffectiverightsfromaclw
#DWORD GetEffectiveRightsFromAclW(
#  PACL         pacl,
#  PTRUSTEE_W   pTrustee,
#  PACCESS_MASK pAccessRights
#);

def GetEffectiveRightsFromAclW(acl, sid):
	"""
	Takes a SID instead of a trustee!
	"""
	_GetEffectiveRightsFromAclW = windll.advapi32.GetEffectiveRightsFromAclW
	_GetEffectiveRightsFromAclW.argtypes = [PVOID, PTRUSTEE_W, PDWORD] #[HANDLE, SE_OBJECT_TYPE, DWORD, PSID, PSID, PACL, PACL, PSECURITY_DESCRIPTOR]
	_GetEffectiveRightsFromAclW.restype  = RaiseIfNotErrorSuccess

	sid_data = sid.to_bytes()
	psid = ctypes.create_string_buffer(sid_data, len(sid_data))
	trustee = TRUSTEE_W()
	trustee.pMultipleTrustee = 0
	trustee.MultipleTrusteeOperation = 0
	trustee.TrusteeForm = 0
	trustee.TrusteeType = 0
	trustee.ptstrName = ctypes.c_void_p(ctypes.addressof(psid))

	effective_rigths_mask = DWORD(0)
	acl_data = acl.to_bytes()
	pacl = ctypes.create_string_buffer(acl_data, len(acl_data))

	res = _GetEffectiveRightsFromAclW(pacl, trustee, byref(effective_rigths_mask))
	return effective_rigths_mask.value

def LookupAccountSidW(lpSystemName, sid_data):
	_LookupAccountSidW = windll.advapi32.LookupAccountSidW
	_LookupAccountSidW.argtypes = [LPSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, LPDWORD]
	_LookupAccountSidW.restype  = bool

	cchName = DWORD(0)
	cchReferencedDomainName = DWORD(0)
	peUse = DWORD(0)
	lpSid = ctypes.create_string_buffer(sid_data, len(sid_data))
	_LookupAccountSidW(lpSystemName, lpSid, None, byref(cchName), None, byref(cchReferencedDomainName), byref(peUse))
	error = GetLastError()
	if error != ERROR_INSUFFICIENT_BUFFER:
		raise ctypes.WinError(error)
	lpName = ctypes.create_unicode_buffer(u'', cchName.value + 1)
	lpReferencedDomainName = ctypes.create_unicode_buffer(u'', cchReferencedDomainName.value + 1)
	success = _LookupAccountSidW(lpSystemName, lpSid, lpName, byref(cchName), lpReferencedDomainName, byref(cchReferencedDomainName), byref(peUse))
	if not success:
		raise ctypes.WinError()
	return lpName.value, lpReferencedDomainName.value, peUse.value

# https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountnamew
def LookupAccountNameW(lpSystemName, accountname):
	_LookupAccountNameW = windll.advapi32.LookupAccountNameW
	_LookupAccountNameW.argtypes = [LPWSTR, LPWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, LPDWORD]
	_LookupAccountNameW.restype  = BOOL

	cbSid = DWORD(0)
	cchReferencedDomainName = DWORD(0)
	peUse = DWORD(0)
	lpAccountName = ctypes.create_unicode_buffer(accountname)
	_LookupAccountNameW(lpSystemName, lpAccountName, None, byref(cbSid), None, byref(cchReferencedDomainName), byref(peUse))
	error = GetLastError()
	if error != ERROR_INSUFFICIENT_BUFFER:
		raise(ctypes.WinError(error))
	sid = ctypes.create_string_buffer(b'', cbSid.value)
	psid = ctypes.cast(ctypes.pointer(sid), PSID)
	lpReferencedDomainName = ctypes.create_unicode_buffer(u'', cchReferencedDomainName.value + 1)
	success = _LookupAccountNameW(lpSystemName, lpAccountName, psid, byref(cbSid), lpReferencedDomainName, byref(cchReferencedDomainName), byref(peUse))
	if not success:
		raise ctypes.WinError()
	
	buff = MemoryBuffer(psid.value)
	sid = SID.from_buffer(buff)
	#LocalFree(psid)
	return sid, lpReferencedDomainName.value, peUse.value


# https://docs.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw
# https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
# https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
SDDL_REVISION_1 = 1

def ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, req_info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION):
	_ConvertSecurityDescriptorToStringSecurityDescriptorW = windll.advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
	_ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [PVOID, DWORD, DWORD, PVOID, PULONG]
	_ConvertSecurityDescriptorToStringSecurityDescriptorW.restype  = DWORD
	_ConvertSecurityDescriptorToStringSecurityDescriptorW.errcheck  = RaiseIfZero

	sd_data = sd.to_bytes()
	psd = ctypes.create_string_buffer(sd_data, len(sd_data))
	pstr = ctypes.pointer(ctypes.c_uint(0))
	pstrsize = ctypes.c_uint(0)

	_ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, SDDL_REVISION_1, req_info, byref(pstr), byref(pstrsize))

	res = ctypes.string_at(pstr, pstrsize.value*2) #multiply by two because the size is not in bytes but in character counts and each char is 2 bytes.... fuck you microsoft
	LocalFree(pstr)
	return res.decode('utf-16-le')

#BOOL QueryServiceObjectSecurity(
#  SC_HANDLE            hService,
#  SECURITY_INFORMATION dwSecurityInformation,
#  PSECURITY_DESCRIPTOR lpSecurityDescriptor,
#  DWORD                cbBufSize,
#  LPDWORD              pcbBytesNeeded
#);

def QueryServiceObjectSecurity(hService, dwSecurityInformation = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd_object_type = None):
	_QueryServiceObjectSecurity = windll.advapi32.QueryServiceObjectSecurity
	_QueryServiceObjectSecurity.argtypes = [SC_HANDLE, DWORD, PVOID, DWORD, LPDWORD]
	_QueryServiceObjectSecurity.restype  = DWORD
	#_QueryServiceObjectSecurity.errcheck = RaiseIfZero

	#first we get the size
	lpSecurityDescriptor = None
	cbBufSize = DWORD(0)
	pcbBytesNeeded = DWORD(0)

	correct_length = 0
	res = _QueryServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded)
	if res == 0:
		#getting the correct length
		correct_length = pcbBytesNeeded.value
	
	lpSecurityDescriptor = ctypes.create_string_buffer(correct_length)
	cbBufSize = DWORD(correct_length)
	pcbBytesNeeded = DWORD(0)

	res = _QueryServiceObjectSecurity(hService, dwSecurityInformation, lpSecurityDescriptor, cbBufSize, pcbBytesNeeded)
	if res == 0:
		raise ctypes.WinError(result)
	buff = ctypes.string_at(lpSecurityDescriptor, pcbBytesNeeded.value)
	sd = SECURITY_DESCRIPTOR.from_bytes(buff, sd_object_type)

	return sd


def OpenSCManagerW(lpMachineName = None, lpDatabaseName = None, dwDesiredAccess = SC_MANAGER_ALL_ACCESS):
	_OpenSCManagerW = windll.advapi32.OpenSCManagerW
	_OpenSCManagerW.argtypes = [LPWSTR, LPWSTR, DWORD]
	_OpenSCManagerW.restype  = SC_HANDLE
	_OpenSCManagerW.errcheck = RaiseIfZero

	hSCObject = _OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess)
	return hSCObject

#
#SC_HANDLE OpenServiceW(
#  SC_HANDLE hSCManager,
#  LPCSTR    lpServiceName,
#  DWORD     dwDesiredAccess
#);

def OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess = SERVICE_ALL_ACCESS):
	_OpenServiceW = windll.advapi32.OpenServiceW
	_OpenServiceW.argtypes = [SC_HANDLE, LPWSTR, DWORD]
	_OpenServiceW.restype  = SC_HANDLE
	_OpenServiceW.errcheck = RaiseIfZero
	return _OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess)

def CloseServiceHandle(hHandle):
	_CloseServiceHandle = windll.advapi32.CloseServiceHandle
	_CloseServiceHandle.argtypes = [HANDLE]
	_CloseServiceHandle.restype  = bool
	_CloseServiceHandle.errcheck = RaiseIfZero
	_CloseServiceHandle(hHandle)


class SERVICE_STATUS(Structure):
	_fields_ = [
		("dwServiceType",               DWORD),
		("dwCurrentState",              DWORD),
		("dwControlsAccepted",          DWORD),
		("dwWin32ExitCode",             DWORD),
		("dwServiceSpecificExitCode",   DWORD),
		("dwCheckPoint",                DWORD),
		("dwWaitHint",                  DWORD),
	]
LPSERVICE_STATUS = POINTER(SERVICE_STATUS)

class ENUM_SERVICE_STATUSW(Structure):
	_fields_ = [
		("lpServiceName", LPWSTR),
		("lpDisplayName", LPWSTR),
		("ServiceStatus", SERVICE_STATUS),
	]
LPENUM_SERVICE_STATUSW = POINTER(ENUM_SERVICE_STATUSW)

def EnumServicesStatusW(hSCManager, dwServiceType = SERVICE_DRIVER | SERVICE_WIN32, dwServiceState = SERVICE_STATE_ALL):
	_EnumServicesStatusW = windll.advapi32.EnumServicesStatusW
	_EnumServicesStatusW.argtypes = [SC_HANDLE, DWORD, DWORD, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD]
	_EnumServicesStatusW.restype  = bool

	cbBytesNeeded    = DWORD(0)
	ServicesReturned = DWORD(0)
	ResumeHandle     = DWORD(0)

	_EnumServicesStatusW(hSCManager, dwServiceType, dwServiceState, None, 0, byref(cbBytesNeeded), byref(ServicesReturned), byref(ResumeHandle))

	Services = []
	success = False
	while GetLastError() == ERROR_MORE_DATA:
		if cbBytesNeeded.value < sizeof(ENUM_SERVICE_STATUSW):
			break
		ServicesBuffer = ctypes.create_string_buffer(b"", cbBytesNeeded.value)
		success = _EnumServicesStatusW(hSCManager, dwServiceType, dwServiceState, byref(ServicesBuffer), sizeof(ServicesBuffer), byref(cbBytesNeeded), byref(ServicesReturned), byref(ResumeHandle))
		if sizeof(ServicesBuffer) < (sizeof(ENUM_SERVICE_STATUSW) * ServicesReturned.value):
			raise ctypes.WinError()
		lpServicesArray = ctypes.cast(ctypes.cast(ctypes.pointer(ServicesBuffer), ctypes.c_void_p), LPENUM_SERVICE_STATUSW)
		for index in range(0, ServicesReturned.value):
			Services.append( lpServicesArray[index].lpServiceName )
		if success: break
	if not success:
		raise ctypes.WinError()

	return Services


HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003
HKEY_PERFORMANCE_DATA = 0x80000004
HKEY_PERFORMANCE_TEXT = 0x80000050
HKEY_PERFORMANCE_NLSTEXT = 0x80000060
HKEY_CURRENT_CONFIG = 0x80000005
HKEY_DYN_DATA = 0x80000006

hive_name_map = {
	'HKLM' : HKEY_LOCAL_MACHINE,
	'HKCU' : HKEY_CURRENT_USER,
	'HKCR' : HKEY_CLASSES_ROOT,
	'HKU'  : HKEY_USERS,
	'HKCC' : HKEY_CURRENT_CONFIG,
	'HKPD' : HKEY_PERFORMANCE_DATA,
}

# https://docs.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys
KEY_ALL_ACCESS = 0xF003F #Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
KEY_CREATE_LINK = 0x0020 #	Reserved for system use.
KEY_CREATE_SUB_KEY = 0x0004 #Required to create a subkey of a registry key.
KEY_ENUMERATE_SUB_KEYS = 0x0008 #Required to enumerate the subkeys of a registry key.
KEY_EXECUTE = 0x20019 #Equivalent to KEY_READ.
KEY_NOTIFY = 0x0010 #Required to request change notifications for a registry key or for subkeys of a registry key.
KEY_QUERY_VALUE = 0x0001 #Required to query the values of a registry key.
KEY_READ = 0x20019 #Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
KEY_SET_VALUE = 0x0002 #Required to create, delete, or set a registry value.
KEY_WOW64_32KEY = 0x0200 #Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. #This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. #Windows 2000: This flag is not supported.
KEY_WOW64_64KEY = 0x0100 #Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
KEY_WRITE = 0x20006 #Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.


REG_OPTION_RESERVED = 0x0000
REG_OPTION_NON_VOLATILE = 0x0000
REG_OPTION_VOLATILE = 0x0001
REG_OPTION_CREATE_LINK = 0x0002
REG_OPTION_BACKUP_RESTORE = 0x0004
REG_OPTION_OPEN_LINK = 0x0008
#REG_LEGAL_OPTION =
#
#    REG_OPTION_RESERVED |
#    REG_OPTION_NON_VOLATILE | REG_OPTION_CREATE_LINK |
#    REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK

# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
def RegOpenKeyExW(regkey_handle, subkey_name = None, options = REG_OPTION_NON_VOLATILE, access = KEY_READ):
	_RegOpenKeyExW = windll.advapi32.RegOpenKeyExA
	_RegOpenKeyExW.argtypes = [HANDLE, LPVOID, DWORD, DWORD, PHANDLE]
	_RegOpenKeyExW.restype  = DWORD
	_RegOpenKeyExW.errcheck = RaiseIfNotErrorSuccess

	psubkey = None
	if subkey_name is not None:
		psd = subkey_name.encode('ascii') #despite the W at the end of the function name, it takes ASCII
		psubkey = ctypes.create_string_buffer(psd, len(psd))

	reshandle = HANDLE()
	ret = _RegOpenKeyExW(regkey_handle, psubkey, options, access, ctypes.byref(reshandle))
	return reshandle

# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
def RegCloseKey(hHandle):
	_RegCloseKey = windll.advapi32.RegCloseKey
	_RegCloseKey.argtypes = [HANDLE]
	_RegCloseKey.restype  = bool
	_RegCloseKey.errcheck = RaiseIfNotErrorSuccess
	_RegCloseKey(hHandle)


# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw
# LSTATUS RegEnumKeyExW(
#  HKEY      hKey,
#  DWORD     dwIndex,
#  LPWSTR    lpName,
#  LPDWORD   lpcchName,
#  LPDWORD   lpReserved,
#  LPWSTR    lpClass,
#  LPDWORD   lpcchClass,
#  PFILETIME lpftLastWriteTime
#);

def RegEnumKeyExW(hKey):
	_RegEnumKeyExW = windll.advapi32.RegEnumKeyExW
	_RegEnumKeyExW.argtypes = [HANDLE, DWORD, PVOID, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PVOID]
	_RegEnumKeyExW.restype  = DWORD

	i = 0
	subkeys = []
	res = ERROR_SUCCESS
	
	while res == ERROR_SUCCESS:
		dwIndex = DWORD(i)
		lpName = ctypes.create_unicode_buffer(255 * 2)
		lpcchName = DWORD(255)

		res = _RegEnumKeyExW(hKey, dwIndex, byref(lpName), byref(lpcchName), NULL, NULL, NULL, NULL)
		if res == ERROR_SUCCESS:
			skname = lpName.value
			subkeys.append(skname)
			i += 1
		elif res == ERROR_NO_MORE_ITEMS:
			break
		else:
			raise ctypes.WinError()

	return subkeys


# https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew
# LSTATUS RegEnumValueW(
#  HKEY    hKey,
#  DWORD   dwIndex,
#  LPWSTR  lpValueName,
#  LPDWORD lpcchValueName,
#  LPDWORD lpReserved,
#  LPDWORD lpType,
#  LPBYTE  lpData,
#  LPDWORD lpcbData
#);

def RegEnumValueW(hKey):
	_RegEnumValueW = windll.advapi32.RegEnumValueW
	_RegEnumValueW.argtypes = [HANDLE, DWORD, PVOID, LPDWORD, PVOID, PVOID, PVOID, PVOID]
	_RegEnumValueW.restype  = DWORD

	i = 0
	subkeys = []
	res = ERROR_SUCCESS
	
	while res == ERROR_SUCCESS:
		dwIndex = DWORD(i)
		lpName = ctypes.create_unicode_buffer(255 * 2)
		lpcchName = DWORD(255)

		res = _RegEnumValueW(hKey, dwIndex, byref(lpName), byref(lpcchName), NULL, NULL, NULL, NULL)
		if res == ERROR_SUCCESS:
			skname = lpName.value
			subkeys.append(skname)
			i += 1
		elif res == ERROR_NO_MORE_ITEMS:
			break
		else:
			raise ctypes.WinError()

	return subkeys


# https://docs.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsharegetinfo
#NET_API_STATUS NET_API_FUNCTION NetShareGetInfo(
#  LMSTR  servername,
#  LMSTR  netname,
#  DWORD  level,
#  LPBYTE *bufptr
#);

def NetShareGetInfo(servername, sharename, level = 502):
	_NetShareGetInfo = windll.netapi32.NetShareGetInfo
	_NetShareGetInfo.argtypes = [PVOID, PVOID, DWORD, PVOID]
	_NetShareGetInfo.restype  = DWORD
	_NetShareGetInfo.errcheck = RaiseIfNotErrorSuccess

	pservername = ctypes.create_string_buffer(servername.encode('ascii'), len(servername.encode('ascii')))
	psharename = ctypes.create_string_buffer(sharename.encode('ascii'), len(sharename.encode('ascii')))
	pbuff = ctypes.pointer(ctypes.c_uint(0))

	_NetShareGetInfo(ctypes.pointer((pservername)), ctypes.pointer(psharename), level, pbuff)
	print(pbuff)
	#LocalFree(cstr_sid)

	return str_sid


# BOOL WINAPI OpenProcessToken(
#   __in   HANDLE ProcessHandle,
#   __in   DWORD DesiredAccess,
#   __out  PHANDLE TokenHandle
# );
def OpenProcessToken(ProcessHandle, DesiredAccess = TOKEN_ALL_ACCESS):
	_OpenProcessToken = windll.advapi32.OpenProcessToken
	_OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
	_OpenProcessToken.restype  = bool
	_OpenProcessToken.errcheck = RaiseIfZero

	NewTokenHandle = HANDLE(INVALID_HANDLE_VALUE)
	_OpenProcessToken(ProcessHandle, DesiredAccess, byref(NewTokenHandle))
	return NewTokenHandle.value

def _internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation):
	_GetTokenInformation = windll.advapi32.GetTokenInformation
	_GetTokenInformation.argtypes = [HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD]
	_GetTokenInformation.restype  = bool
	_GetTokenInformation.errcheck = RaiseIfZero

	ReturnLength = DWORD(0)
	TokenInformationLength = SIZEOF(TokenInformation)
	_GetTokenInformation(hTokenHandle, TokenInformationClass, byref(TokenInformation), TokenInformationLength, byref(ReturnLength))
	if ReturnLength.value != TokenInformationLength:
		raise ctypes.WinError(ERROR_INSUFFICIENT_BUFFER)
	return TokenInformation

# typedef enum tagTOKEN_TYPE {
#   TokenPrimary         = 1,
#   TokenImpersonation
# } TOKEN_TYPE, *PTOKEN_TYPE;

TOKEN_TYPE = ctypes.c_int
PTOKEN_TYPE = POINTER(TOKEN_TYPE)


# typedef struct _LUID {
#   DWORD LowPart;
#   LONG HighPart;
# } LUID,
#  *PLUID;
class LUID(Structure):
	_fields_ = [
		("LowPart",     DWORD),
		("HighPart",    LONG),
	]

PLUID = POINTER(LUID)

# typedef enum _SECURITY_IMPERSONATION_LEVEL {
#   SecurityAnonymous,
#   SecurityIdentification,
#   SecurityImpersonation,
#   SecurityDelegation
# } SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

SecurityAnonymous       = 0
SecurityIdentification  = 1
SecurityImpersonation   = 2
SecurityDelegation      = 3

SECURITY_IMPERSONATION_LEVEL = ctypes.c_int
PSECURITY_IMPERSONATION_LEVEL = POINTER(SECURITY_IMPERSONATION_LEVEL)


# typedef struct _TOKEN_STATISTICS {
#   LUID                         TokenId;
#   LUID                         AuthenticationId;
#   LARGE_INTEGER                ExpirationTime;
#   TOKEN_TYPE                   TokenType;
#   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
#   DWORD                        DynamicCharged;
#   DWORD                        DynamicAvailable;
#   DWORD                        GroupCount;
#   DWORD                        PrivilegeCount;
#   LUID                         ModifiedId;
# } TOKEN_STATISTICS, *PTOKEN_STATISTICS;
class TOKEN_STATISTICS(Structure):
	_fields_ = [
		("TokenId",             LUID),
		("AuthenticationId",    LUID),
		("ExpirationTime",      LONGLONG),  # LARGE_INTEGER
		("TokenType",           TOKEN_TYPE),
		("ImpersonationLevel",  SECURITY_IMPERSONATION_LEVEL),
		("DynamicCharged",      DWORD),
		("DynamicAvailable",    DWORD),
		("GroupCount",          DWORD),
		("PrivilegeCount",      DWORD),
		("ModifiedId",          LUID),
	]
PTOKEN_STATISTICS = POINTER(TOKEN_STATISTICS)

# BOOL WINAPI GetTokenInformation(
#   __in       HANDLE TokenHandle,
#   __in       TOKEN_INFORMATION_CLASS TokenInformationClass,
#   __out_opt  LPVOID TokenInformation,
#   __in       DWORD TokenInformationLength,
#   __out      PDWORD ReturnLength
# );
def GetTokenInformation(hTokenHandle, TokenInformationClass):
	if TokenInformationClass <= 0 or TokenInformationClass > MaxTokenInfoClass:
		raise ValueError("Invalid value for TokenInformationClass (%i)" % TokenInformationClass)

	# Token statistics.
	if TokenInformationClass == TokenStatistics:
		TokenInformation = TOKEN_STATISTICS()
		_internal_GetTokenInformation(hTokenHandle, TokenInformationClass, TokenInformation)
		return TokenInformation # TODO add a class wrapper?

class LSA_LAST_INTER_LOGON_INFO(Structure):
	_fields_ = [
		("LastSuccessfulLogon", LONGLONG),
		("LastFailedLogon", LONGLONG),
		("FailedAttemptCountSinceLastSuccessfulLogon", ULONG),
	]
PLSA_LAST_INTER_LOGON_INFO = POINTER(LSA_LAST_INTER_LOGON_INFO)

class SECURITY_LOGON_SESSION_DATA(Structure):
	_fields_ = [
		("Size", ULONG),
		("LogonId", LUID),
		("UserName", UNICODE_STRING),
		("LogonDomain", UNICODE_STRING),
		("AuthenticationPackage", UNICODE_STRING),
		("Session", ULONG),
		("Sid", PSID),
		("LogonTime", LONGLONG),
		("LogonServer", UNICODE_STRING),
		("DnsDomainName", UNICODE_STRING),
		("Upn", UNICODE_STRING),
		("UserFlags", ULONG),
		("LastLogonInfo", LSA_LAST_INTER_LOGON_INFO),
		("LogonScript", UNICODE_STRING),
		("ProfilePath", UNICODE_STRING),
		("HomeDirectory", UNICODE_STRING),
		("HomeDirectoryDrive", UNICODE_STRING),
		("LogoffTime", LONGLONG),
		("KickOffTime", LONGLONG),
		("PasswordLastSet", LONGLONG),
		("PasswordCanChange", LONGLONG),
		("PasswordMustChange", LONGLONG),
	]
PSECURITY_LOGON_SESSION_DATA = POINTER(SECURITY_LOGON_SESSION_DATA)

def LsaGetLogonSessionData(luid):
	_LsaGetLogonSessionData = windll.Secur32.LsaGetLogonSessionData
	_LsaGetLogonSessionData.argtypes = [PLUID, POINTER(PSECURITY_LOGON_SESSION_DATA)]
	_LsaGetLogonSessionData.restype  = DWORD
	#_LsaGetLogonSessionData.errcheck = RaiseIfNotErrorSuccess

	secdata = PSECURITY_LOGON_SESSION_DATA()

	x = _LsaGetLogonSessionData(luid, byref(secdata))
	res = {
		'username' : secdata.contents.UserName.get_string(),
		'usersid' : ConvertSidToStringSidW(secdata.contents.Sid, True),
		'domain' : secdata.contents.LogonDomain.get_string(),
		'logonserver' : secdata.contents.LogonServer.get_string(),
		'dnsdomainname' : secdata.contents.DnsDomainName.get_string(),
	}
	return res

# DWORD WINAPI GetCurrentProcessId(void);
def GetCurrentProcessId():
	_GetCurrentProcessId = windll.kernel32.GetCurrentProcessId
	_GetCurrentProcessId.argtypes = []
	_GetCurrentProcessId.restype  = DWORD
	return _GetCurrentProcessId()

# HANDLE WINAPI OpenProcess(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwProcessId
# );
def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
	_OpenProcess = windll.kernel32.OpenProcess
	_OpenProcess.argtypes = [DWORD, BOOL, DWORD]
	_OpenProcess.restype  = HANDLE

	if dwDesiredAccess is None:
		dwDesiredAccess = 0x10000000
	hProcess = _OpenProcess(dwDesiredAccess, bool(bInheritHandle), dwProcessId)
	if hProcess == NULL:
		raise ctypes.WinError()
	return hProcess
