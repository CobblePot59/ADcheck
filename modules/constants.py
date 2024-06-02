# https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdproperties
PWD_PROPERTIES = {
    1: "DOMAIN_PASSWORD_COMPLEX",
    2: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
    4: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
    8: "DOMAIN_LOCKOUT_ADMINS",
    16: "DOMAIN_PASSWORD_STORE_CLEARTEXT",
    32: "DOMAIN_REFUSE_PASSWORD_CHANGE"
}

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/564dc969-6db3-49b3-891a-f2f8d0a68a7f
FOREST_LEVELS = {
    7: "Windows Server 2016",
    6: "Windows Server 2012 R2",
    5: "Windows Server 2012",
    4: "Windows Server 2008 R2",
    3: "Windows Server 2008",
    2: "Windows Server 2003",
    1: "Windows Server 2003 operating system through Windows Server 2016",
    0: "Windows 2000 Server operating system through Windows Server 2008 operating system"
}

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#list-of-property-flags
USER_ACCOUNT_CONTROL = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PASSWORD_ALLOWED": 0x0080,
    "TEMP_DUPLICATE_ACCOUNT": 0x0100,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "MNS_LOGON_ACCOUNT": 0x20000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "NO_AUTH_DATA_REQUIRED": 0x02000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000
}

# https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797
SUPPORTED_ENCRYPTION = {
    0: "RC4_HMAC_MD5",
    1: "DES_CBC_CRC",
    2: "DES_CBC_MD5",
    3: "DES_CBC_CRC, DES_CBC_MD5",
    4: "RC4",
    5: "DES_CBC_CRC, RC4",
    6: "DES_CBC_MD5, RC4",
    7: "DES_CBC_CRC, DES_CBC_MD5, RC4",
    8: "AES 128",
    9: "DES_CBC_CRC, AES 128",
    10: "DES_CBC_MD5, AES 128",
    11: "DES_CBC_CRC, DES_CBC_MD5, AES 128",
    12: "RC4, AES 128",
    13: "DES_CBC_CRC, RC4, AES 128",
    14: "DES_CBC_MD5, RC4, AES 128",
    15: "DES_CBC_CBC, DES_CBC_MD5, RC4, AES 128",
    16: "AES 256",
    17: "DES_CBC_CRC, AES 256",
    18: "DES_CBC_MD5, AES 256",
    19: "DES_CBC_CRC, DES_CBC_MD5, AES 256",
    20: "RC4, AES 256",
    21: "DES_CBC_CRC, RC4, AES 256",
    22: "DES_CBC_MD5, RC4, AES 256",
    23: "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256",
    24: "AES 128, AES 256",
    25: "DES_CBC_CRC, AES 128, AES 256",
    26: "DES_CBC_MD5, AES 128, AES 256",
    27: "DES_CBC_MD5, DES_CBC_MD5, AES 128, AES 256",
    28: "RC4, AES 128, AES 256",
    29: "DES_CBC_CRC, RC4, AES 128, AES 256",
    30: "DES_CBC_MD5, RC4, AES 128, AES 256",
    31: "DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96"
}

PRIVESC_GROUP = [
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Enterprise Key Admins",
    "Key Admins",
    "Schema Admins",
    "Replicator",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "DnsAdmins",
    "Account Operators",
    "Remote Desktop Users",
    "Certificate Operators",
    "Cert Publishers"
]

# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids
WELL_KNOWN_SIDS = {
    "S-1-0-0": "SID Null",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner ID",
    "S-1-3-1": "Creator Group ID",
    "S-1-3-2": "Owner Server",
    "S-1-3-3": "Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-80-0": "All Services",
    "S-1-5-1": "Dialup",
    "S-1-5-113": "Local account",
    "S-1-5-114": "Local account and member of Administrators group",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-5": "Logon session",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous logon",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Interactive logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "System (or Local System)",
    "S-1-5-19": "NT Authority (Local Service)",
    "S-1-5-20": "Network Service",
    "domain-500": "Administrator",
    "domain-501": "Guest",
    "domain-502": "KRBTGT",
    "domain-512": "Domain Admins",
    "domain-513": "Domain Users",
    "domain-514": "Domain Guests",
    "domain-515": "Domain Computers",
    "domain-516": "Domain Controllers",
    "domain-517": "Cert Publishers", # Certificate Publishers
    "domain-518": "Schema Admins",
    "domain-519": "Enterprise Admins",
    "domain-520": "Group Policy Creator Owners",
    "domain-521": "Read-only Domain Controllers",
    "domain-522": "Cloneable Domain Controllers", # Cloneable Controllers
    "domain-525": "Protected Users",
    "domain-526": "Key Admins",
    "domain-527": "Enterprise Key Admins",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "domain-553": "RAS and IAS Servers",
    "S-1-5-32-554": "Builtin\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "Builtin\\Remote Desktop Users",
    "S-1-5-32-556": "Builtin\\Network Configuration Operators",
    "S-1-5-32-557": "Builtin\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "Builtin\\Performance Monitor Users",
    "S-1-5-32-559": "Builtin\\Performance Log Users",
    "S-1-5-32-560": "Builtin\\Windows Authorization Access Group",
    "S-1-5-32-561": "Builtin\\Terminal Server License Servers",
    "S-1-5-32-562": "Builtin\\Distributed COM Users",
    "S-1-5-32-568": "Builtin\\IIS_IUSRS",
    "S-1-5-32-569": "Builtin\\Cryptographic Operators",
    # NOT IN LIST
    "domain-498": "Enterprise Read-only Domain Controllers",
    "domain-571": "Allowed RODC Password Replication Group",
    "domain-572": "Denied RODC Password Replication Group",
    "domain-1102": "DnsUpdateProxy",
    "S-1-5-32-579": "Builtin\\Access Control Assistance Operators",
    "S-1-5-32-574": "Builtin\\Certificate Service DCOM Access",
    "S-1-5-32-573": "Builtin\\Event Log Readers",
    "S-1-5-32-578": "Builtin\\Hyper-V Administrators",
    "S-1-5-32-576": "Builtin\\RDS Endpoint Servers",
    "S-1-5-32-577": "Builtin\\RDS Management Servers",
    "S-1-5-32-575": "Builtin\\RDS Remote Access Servers",
    "S-1-5-32-580": "Builtin\\Remote Management Users",
    "S-1-5-32-582": "Builtin\\Storage Replica Administrators",
    "S-1-5-90-0": "System Managed Accounts Group"
}

# https://learn.microsoft.com/en-us/windows/win32/wmisdk/file-and-directory-access-rights-constants
FILE_ACCESS_RIGHT = {
    1: "read data from the file",
    2: "write data to the file",
    4: "append data to the file",
    8: "read extended attributes",
    16: "write extended attributes",
    32: "execute the file",
    128: "read file attributes",
    256: "change file attributes",
    65536: "delete the object",
    131072: "read the information in the security descriptor from the file",
    262144: "modify the DACL to the file",
    524288: "change the owner in the security descriptor to the file",
    1048576: "use the object for synchronization"
}

DIRECTORY_ACCESS_RIGHT = {
    1: "list the contents of the directory",
    2: "create a file in the directory",
    4: "create a subdirectory",
    8: "read extended attributes",
    16: "write extended attributes",
    32: "be traversed",
    64: "delete the directory and all the files it contains",
    65536: "delete the object",
    131072: "read the information in the security descriptor from the directory",
    262144: "modify the DACL to the directory",
    524288: "change the owner in the security descriptor to the directory",
    1048576: "use the object for synchronization"
}

# https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-8.0#fields
# ENTRANCE_ACCESS_CONTROL = {
#     "AccessSystemSecurity": 16777216,
#     "CreateChild": 1,
#     "Delete": 65536,
#     "DeleteChild": 2,
#     "DeleteTree": 64,
#     "ExtendedRight": 256,
#     "GenericAll": 983551,
#     "GenericExecute": 131076,
#     "GenericRead": 131220,
#     "GenericWrite": 131112,
#     "ListChildren": 4,
#     "ListObject": 128,
#     "ReadControl": 131072,
#     "ReadProperty": 16,
#     "Self": 8,
#     "Synchronize": 1048576,
#     "WriteDacl": 262144,
#     "WriteOwner": 524288,
#     "WriteProperty": 32
# }

ENTRANCE_ACCESS_CONTROL = {
    "Create all child objects": 1,
    "Delete": 65536,
    "Delete all child objects": 2,
    "Delete subtree": 64,
    "All extended rights": 256,
    "Full control": 983551,
    "List contents": 4,
    "Read permissions": 131072,
    "Read all properties": 16,
    "All validated writes": 8,
    "Modify permissions": 262144,
    "Modify owner": 524288,
    "Write all properties": 32
}

LAPS_PROPERTIES_UUID = {
    'msLAPS-EncryptedDSRMPassword' : b'/\xa87\x9e\xa2C!G\x98=7K\x82\xfd\xc0\xfa',
    'msLAPS-EncryptedDSRMPasswordHistory' : b'\x10\xc6\xa9\x11\xa4?\xa2E\xbc\x04\x8dl\xdf\xdaw`',
    'msLAPS-EncryptedPassword' : b"F;\xbc_y]+@\x8c~\xfc\xcal'\xb9\xc2",
    'msLAPS-EncryptedPasswordHistory' : b'D\x8aJ\xb8j\xac\xcfA\x87\x1c\xaf\xf1.\xfd{d',
    'msLAPS-Password' : b"\xe1\xec\x9c'\xbfq\x99B\x86\xe8\xff\xe0\xe9\xe5\x01.",
    'msLAPS-PasswordExpirationTime' : b't\xdehF\x88\xa48K\xaf\xf8\xcf\x9fB\x8e\x89\xaa',
}

DELEGATIONS_ACE = {
    "[{'PermissionsValue': ['Create all child objects', 'Delete all child objects'], 'PermissionsObjects': ['User'], 'InheritedObjectType': None}, {'PermissionsValue': 'Full control', 'PermissionsObjects': [], 'InheritedObjectType': ['User']}]": "Create, delete and manage user accounts",
    "[{'PermissionsValue': ['All extended rights'], 'PermissionsObjects': ['Reset Password'], 'InheritedObjectType': ['User']}, {'PermissionsValue': ['Read all properties', 'Write all properties'], 'PermissionsObjects': ['Pwd-Last-Set'], 'InheritedObjectType': ['User']}]": "Reset user passwords and force password change at next logon",
    "[{'PermissionsValue': ['Read all properties'], 'PermissionsObjects': [], 'InheritedObjectType': ['User']}]": "Read all user information",
    "[{'PermissionsValue': ['Create all child objects', 'Delete all child objects'], 'PermissionsObjects': ['Group'], 'InheritedObjectType': None}, {'PermissionsValue': 'Full control', 'PermissionsObjects': [], 'InheritedObjectType': ['Group']}]": "Create, delete and manage groups",
    "[{'PermissionsValue': ['Read all properties', 'Write all properties'], 'PermissionsObjects': ['Member'], 'InheritedObjectType': ['Group']}]": "Modfy the membership of a group",
    "[{'PermissionsValue': ['Read all properties', 'Write all properties'], 'PermissionsObjects': ['GP-Link'], 'InheritedObjectType': None}, {'PermissionsValue': ['Read all properties', 'Write all properties'], 'PermissionsObjects': ['GP-Options'], 'InheritedObjectType': None}]": "Manage Group Policy links",
    "[{'PermissionsValue': ['All extended rights'], 'PermissionsObjects': ['Generate Resultant Set of Policy (Planning)'], 'InheritedObjectType': None}]": "Generate Resultant Set of Policy (Planning)",
    "[{'PermissionsValue': ['All extended rights'], 'PermissionsObjects': ['Generate Resultant Set of Policy (Logging)'], 'InheritedObjectType': None}]": "Generate Resultant Set of Policy (Logging)",
    "[{'PermissionsValue': ['Create all child objects', 'Delete all child objects'], 'PermissionsObjects': ['inetOrgPerson'], 'InheritedObjectType': None}, {'PermissionsValue': 'Full control', 'PermissionsObjects': [], 'InheritedObjectType': ['inetOrgPerson']}]": "Create. delete, and manage inetOrgPerson accounts",
    "[{'PermissionsValue': ['All extended rights'], 'PermissionsObjects': ['Reset Password'], 'InheritedObjectType': ['inetOrgPerson']}, {'PermissionsValue': ['Read all properties', 'Write all properties'], 'PermissionsObjects': ['Pwd-Last-Set'], 'InheritedObjectType': ['inetOrgPerson']}]": "Reset inetOrgPerson passwords and force password change at next logon",
    "[{'PermissionsValue': ['Read all properties'], 'PermissionsObjects': [], 'InheritedObjectType': ['inetOrgPerson']}]": "Read all inetOrgPerson information",
    "[{'PermissionsValue': ['Create all child objects'], 'PermissionsObjects': ['Computer'], 'InheritedObjectType': None}]": "Join a computer to the domain",
    "[{'PermissionsValue': ['Create all child objects', 'Delete all child objects'], 'PermissionsObjects': ['ms-WMI-Som'], 'InheritedObjectType': None}, {'PermissionsValue': 'Full control', 'PermissionsObjects': [], 'InheritedObjectType': ['ms-WMI-Som']}]": "Create, Delete and Manage WMI Filters",
    "[{'PermissionsValue': ['Read all properties'], 'PermissionsObjects': ['msLAPS-Password'], 'InheritedObjectType': ['Computer']}]": "Read LAPS password",
}

# https://learn.microsoft.com/fr-fr/windows/win32/sysinfo/registry-key-security-and-access-rights
REGISTRY_ACCESS_RIGHT = {
    1: 'KEY_QUERY_VALUE',
    2: 'KEY_SET_VALUE',
    4: 'KEY_CREATE_SUB_KEY',
    8: 'KEY_ENUMERATE_SUB_KEYS',
    16: 'KEY_NOTIFY',
    32: 'KEY_CREATE_LINK',
    256: 'KEY_WOW64_64KEY',
    512: 'KEY_WOW64_32KEY',
    131078: 'KEY_WRITE',
    131097: 'KEY_READ',
    983103: 'KEY_ALL_ACCESS'
}
