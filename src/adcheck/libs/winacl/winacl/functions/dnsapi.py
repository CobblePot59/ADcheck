
from winacl.functions.defines import *
import enum
import ctypes
from winacl.functions.kernel32 import GetLastError, LocalFree, READ_CONTROL

class DnsConfig(enum.Enum):
	PrimaryDomainName_W = 0
	PrimaryDomainName_A = 1
	PrimaryDomainName_UTF8 = 2
	AdapterDomainName_W = 3
	AdapterDomainName_A = 4
	AdapterDomainName_UTF8 = 5
	DnsServerList = 6
	SearchList = 7
	AdapterInfo = 8
	PrimaryHostNameRegistrationEnabled = 9
	AdapterHostNameRegistrationEnabled = 10
	AddressRegistrationMaxCount = 11
	HostName_W = 12
	HostName_A = 13
	HostName_UTF8 = 14
	FullHostName_W = 15
	FullHostName_A = 16
	FullHostName_UTF8 = 17
	NameServer = 18

def DnsQueryConfig(dnsconfig, adaptername):
	_DnsQueryConfig = windll.Dnsapi.DnsQueryConfig
	_DnsQueryConfig.argtypes = [DWORD, DWORD, PVOID, PVOID, PVOID, PDWORD]
	_DnsQueryConfig.restype  = DWORD
	_DnsQueryConfig.errcheck = RaiseIfNotErrorSuccess

	if isinstance(adaptername, str):
		padaptername = ctypes.create_unicode_buffer(adaptername)

	bufptr = ctypes.create_string_buffer(1024)
	buflenptr = ctypes.pointer(DWORD(1024))

	_DnsQueryConfig(dnsconfig.value, 0, padaptername, None, byref(bufptr), buflenptr)

	data = ctypes.string_at(bufptr, buflenptr.contents.value)

	return data

def DnsQueryConfig_ServerList(adaptername):
	data = DnsQueryConfig(DnsConfig.DnsServerList, adaptername)

