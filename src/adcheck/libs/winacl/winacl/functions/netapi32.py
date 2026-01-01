from winacl.functions.defines import *

class LOCALGROUP_USERS_INFO_0(Structure):
	_fields_ = [
		("lgrui0_name", LPWSTR),
	]
PLOCALGROUP_USERS_INFO_0 = ctypes.POINTER(LOCALGROUP_USERS_INFO_0)

class USER_INFO_0(Structure):
	_fields_ = [
		("usri0_name", LPWSTR),
	]
PUSER_INFO_0 = ctypes.POINTER(USER_INFO_0)

LG_INCLUDE_INDIRECT = 1


# https://docs.microsoft.com/en-us/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree


def NetApiBufferFree(pBuffer):
	_NetApiBufferFree = windll.netapi32.NetApiBufferFree
	_NetApiBufferFree.argtypes = [HLOCAL]
	_NetApiBufferFree.restype  = DWORD
	_NetApiBufferFree.errcheck = RaiseIfNotErrorSuccess

	_NetApiBufferFree(pBuffer)

#NET_API_STATUS NET_API_FUNCTION NetUserGetLocalGroups(
#  LPCWSTR servername,
#  LPCWSTR username,
#  DWORD   level,
#  DWORD   flags,
#  LPBYTE  *bufptr,
#  DWORD   prefmaxlen,
#  LPDWORD entriesread,
#  LPDWORD totalentries
#);

# https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetlocalgroups
def NetUserGetLocalGroups(server_name, user_name, flags = 0):
	'''
	flags can be 0 or LG_INCLUDE_INDIRECT to include all indirect group memberships
	'''
	_NetUserGetLocalGroups = windll.netapi32.NetUserGetLocalGroups
	_NetUserGetLocalGroups.argtypes = [LPWSTR, LPWSTR, DWORD, DWORD, PVOID, DWORD, LPDWORD, LPDWORD]
	_NetUserGetLocalGroups.restype  = DWORD
	_NetUserGetLocalGroups.errcheck = RaiseIfNotErrorSuccess

	membership_goups = []
	pserver_name = None
	if server_name is not None:
		pserver_name = ctypes.create_unicode_buffer(server_name)
	puser_name = ctypes.create_unicode_buffer(user_name)
	level = 0
	bufptr = ctypes.pointer(DWORD(0))
	prefmaxlen = -1
	entriesread = DWORD(0)
	totalentries = DWORD(0)

	_NetUserGetLocalGroups(
		pserver_name, 
		puser_name, 
		level, 
		flags, 
		byref(bufptr), 
		prefmaxlen, 
		ctypes.byref(entriesread), 
		ctypes.byref(totalentries)
	)
	#print(entriesread)
	#print(totalentries)

	elems = (LOCALGROUP_USERS_INFO_0 * entriesread.value)
	res = ctypes.cast(addressof(bufptr.contents), ctypes.POINTER(elems))
	for i in range(0, entriesread.value):
		membership_goups.append(res.contents[i].lgrui0_name)

	NetApiBufferFree(addressof(bufptr.contents))

	return membership_goups


# https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo

#NET_API_STATUS NET_API_FUNCTION NetUserGetInfo(
#  LPCWSTR servername,
#  LPCWSTR username,
#  DWORD   level,
#  LPBYTE  *bufptr
#);
def NetUserGetInfo(server_name, user_name): #level = 0
	_NetUserGetInfo = windll.netapi32.NetUserGetInfo
	_NetUserGetInfo.argtypes = [LPWSTR, LPWSTR, DWORD, LPDWORD]
	_NetUserGetInfo.restype  = DWORD
	_NetUserGetInfo.errcheck = RaiseIfNotErrorSuccess

	level = 0
	pserver_name = None
	if server_name is not None:
		pserver_name = ctypes.create_unicode_buffer(server_name)
	puser_name = None
	if user_name is not None:
		puser_name = ctypes.create_unicode_buffer(user_name)
	bufptr = ctypes.pointer(DWORD(0))

	_NetUserGetInfo(
		pserver_name, 
		puser_name, 
		level, 
		bufptr
	)

	res = ctypes.cast(addressof(bufptr.contents), PUSER_INFO_0)
	print(res)
	NetApiBufferFree(addressof(bufptr.contents))
