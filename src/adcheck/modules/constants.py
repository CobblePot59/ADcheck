CHECKLIST = {
    "LOW PRIVILEGE MODULES": [
        {
            "User Account Management": [
                ("was_admin", "Accounts that had admin rights in the past"),
                ("timeroast", "Accounts vulnerable to timeroasting attack"),
                ("reversible_password", "Accounts which have reversible passwords"),
                ("pre2000_group", "Name of Pre-Windows 2000 Compatible Access group members"),
                ("password_not_required", "Accounts with password not required"),
                ("native_admin_logon", "Verify if The native administrator account has been used recently"),
                ("locked_accounts", "Locked accounts"),
                ("kerberoast", "Accounts vulnerable to KerbeRoasting attack"),
                ("inactive_accounts", "Number of inactive accounts"),
                ("des_authentication", "Accounts which can use DES authentication"),
                ("auth_attributes", "Accounts with altSecurityIdentities attributes"),
                ("", "Accounts with userPassword attributes"),
                ("", "Accounts with unixUserPassword attributes"),
                ("", "Accounts with unicodePwd attributes"),
                ("", "Accounts with msDS-HostServiceAccount attributes"),
                ("asreproast", "Accounts vulnerable to ASRepRoasting attack"),
                ("admins_schema", "Number of accounts in 'Schema Admins' group"),
                ("admin_not_protected", "Admin accounts not in 'Protected Users' group"),
                ("admin_can_be_delegated", "Admin accounts that can be delegated"),
                ("accounts_never_expire", "Number of accounts which have never expiring passwords"),
                ("privesc_group", "Get List of users in Privesc group", "INFO"),
                ("gMSA", "Get Group Managed Service Accounts", "INFO"),
                ("users_description", "Get Users with description", "INFO")
            ],
            "Audit and Policy Management": [
                ("get_policies", "Dowload Group Policy Objects"),
                ("gpp_password", "Name of Group Policy containing a password"),
                ("force_logoff", "Verify if Force logoff when logon hours expire"),
                ("password_policy", "Get Default password policy", "INFO"),
                ("gpo_by_ou", "Get Group Policy Object by Organizational Unit", "INFO")
            ],
            "Computer and Domain Management": [
                ("smb_signing", "Verify if SMB signing is required"),
                ("recycle_bin", "Verify if Recycle Bin is enabled"),
                ("ldap_signing", "Verify if LDAP signature was required on target"),
                ("channel_binding", "Verify if Channel binding is enforced"),
                ("krbtgt_password_age", "Verify if Kerberos password last changed < 40 days"),
                ("can_add_computer", "Verify if Non-admin users can add up to 10 computer(s) to a domain"),
                ("ldap_anonymous", "Verify LDAP anonymous binding"),
                ("supported_encryption", "Get Supported encryption by Domain Controllers", "INFO"),
                ("pso", "Get Password Settings Object", "INFO"),
                ("krbtgt_encryption", "Get Supported Kerberos encryption algorithms", "INFO"),
                ("kerberos_hardened", "Get Kerberos config", "INFO"),
                ("functional_level", "Get Functional level of domain", "INFO"),
                ("domain_controlers", "Get Domain Controllers", "INFO"),
                ("bitlocker", "Computers with bitlocker keys", "INFO"),
                ("dfsr", "Verify if DFSR SYSVOL is enabled")
            ],
            "Privilege and Trust Management": [
                ("trusted_for_delegation", "Name of Trust accounts for the delegation"),
                ("rbac", "Name of Computers with rbac"),
                ("constrained_delegation", "Computers with constrained delegation"),
                ("can_update_dns", "Verify if User can create dns record"),
                ("silos", "Get Authentication policy silos", "INFO"),
                ("priv_rights", "Get Privilege Rights (SeDebugPrivilege, SeBackupPrivilege, ...)", "INFO"),
                ("policies_ace", "Get Group policy folder/file rights", "INFO")
            ]
        }
    ],
    "\nHIGH PRIVILEGE MODULES (requires admin privs)": [
        {
            "User Account Management": [
                ("identical_password", "Number of accounts with identical passwords"),
                ("blank_password", "Accounts with blank password")
            ],
            "Audit and Policy Management": [
                ("audit_policy", "Get Audit Policy"),
                ("reg_uac", "Verify if UAC configuration is secure"),
                ("reg_AlwaysInstallElevated", "Verify if MSI packages are always installed with elevated privileges"),
                ("reg_CredentialGuard", "Verify if CredentialGuard is enabled"),
                ("reg_LMHASH", "Verify if LM hash storage disabled"),
                ("reg_NTLMv2", "Verify if Authentication limited to NTLMv2 mechanism only"),
                ("reg_applocker", "Verify if AppLocker rules defined"),
                ("reg_autologin", "Verify if gpp_autologon is enabled"),
                ("reg_av", "Get Name of AMSI installed", "INFO"),
                ("reg_bitlocker", "Verify if Bitlocker is enabled"),
                ("reg_fw", "Verify if Firewall is disabled"),
                ("reg_ipv4_only", "Verify if IPv4 preferred over IPv6"),
                ("reg_llmnr", "Verify if LLMNR, NetBIOS ou mDNS is enabled"),
                ("reg_lsa_cache", "Verify if Too many logons are kept in the LSA cache"),
                ("reg_lsass_ppl", "Verify if Lsass runs as a protected process"),
                ("reg_pwsh2", "Verify if Powershell v2 is enabled"),
                ("reg_pwsh_event", "Verify if Powershell events are logged"),
                ("reg_pwsh_restricted", "Verify if Powershell is configured in Restricted mode"),
                ("reg_rdp_nla", "Verify if RDP use NLA"),
                ("reg_rdp_nopth", "Verify if RDP is secured over pass the hash attack"),
                ("reg_rdp_timeout", "Verify if RDP session timeout is too short"),
                ("reg_wdigest", "Verify if WDigest authentication enabled"),
                ("reg_wpad", "Verify if WPAD is disabled"),
                ("reg_wsh", "Verify if Windows Script Host is disabled"),
                ("reg_wsus_config", "Verify if WSUS server is not used"),
                ("reg_ca", "Verify status of Trusted Root Certification Authorities")
            ],
            "Computer and Domain Management": [
                ("wmi_last_backup", "Verify if The computer was recently backed up"),
                ("wmi_last_update", "Verify if The computer is up to date"),
                ("laps", "Verify if LAPS is installed")
            ],
            "Privilege and Trust Management": [
                ("reg_ace", "Registry access rights", "INFO"),
                ("control_delegations", "Get Control delegations by container", "INFO"),
                ("reg_winrm", "Get WSManConfig", "INFO"),
                ("share_ace", "List SMB shares and their ACL ")
            ]
        },
    ]
}

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
    10: "Windows Server 2025",
    7: "Windows Server 2016",
    6: "Windows Server 2012 R2",
    5: "Windows Server 2012",
    4: "Windows Server 2008 R2",
    3: "Windows Server 2008",
    2: "Windows Server 2003",
    1: "Windows Server 2003 operating system through Windows Server 2016",
    0: "Windows 2000 Server operating system through Windows Server 2008 operating system"
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

PRIVESC_GROUP = {
    "S-1-5-32-544": "Administrators",
    "domain-512": "Domain Admins",
    "domain-519": "Enterprise Admins",
    "domain-527": "Enterprise Key Admins",
    "domain-526": "Key Admins",
    "domain-518": "Schema Admins",
    "S-1-5-32-552": "Replicator",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-550": "Print Operators",
    "domain-1101": "DnsAdmins",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-574": "Certificate Operators",
    "domain-517": "Cert Publishers",
}

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
    "S-1-5-90-0": "System Managed Accounts Group",
    "S-1-15-2-1": "All Application Packages"
}

SENSITIVE_TRUSTEES = ["everyone", "anonymous", "authenticated user", "guest"]

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

# ENTRANCE_ACCESS_CONTROL = {
#     "Create all child objects": 1,
#     "Delete": 65536,
#     "Delete all child objects": 2,
#     "Delete subtree": 64,
#     "All extended rights": 256,
#     "Full Control": 983551,
#     "List contents": 4,
#     "Read permissions": 131072,
#     "Read all properties": 16,
#     "All validated writes": 8,
#     "Modify permissions": 262144,
#     "Modify owner": 524288,
#     "Write all properties": 32
# }

# LAPS_PROPERTIES_UUID = {
#     "msLAPS-EncryptedDSRMPassword" : b"/\xa87\x9e\xa2C!G\x98=7K\x82\xfd\xc0\xfa",
#     "msLAPS-EncryptedDSRMPasswordHistory" : b"\x10\xc6\xa9\x11\xa4?\xa2E\xbc\x04\x8dl\xdf\xdaw`",
#     "msLAPS-EncryptedPassword" : b"F;\xbc_y]+@\x8c~\xfc\xcal'\xb9\xc2",
#     "msLAPS-EncryptedPasswordHistory" : b"D\x8aJ\xb8j\xac\xcfA\x87\x1c\xaf\xf1.\xfd{d",
#     "msLAPS-Password" : b"\xe1\xec\x9c'\xbfq\x99B\x86\xe8\xff\xe0\xe9\xe5\x01.",
#     "msLAPS-PasswordExpirationTime" : b"t\xdehF\x88\xa48K\xaf\xf8\xcf\x9fB\x8e\x89\xaa",
# }

# https://learn.microsoft.com/fr-fr/windows/win32/sysinfo/registry-key-security-and-access-rights
# REGISTRY_ACCESS_RIGHT = {
#     "KEY_QUERY_VALUE": 1,
#     "KEY_SET_VALUE": 2,
#     "KEY_CREATE_SUB_KEY": 4,
#     "KEY_ENUMERATE_SUB_KEYS": 8,
#     "KEY_NOTIFY": 16,
#     "KEY_CREATE_LINK": 32,
#     "KEY_WOW64_64KEY": 256,
#     "KEY_WOW64_32KEY": 512,
#     "KEY_WRITE": 131078,
#     "KEY_READ": 131097,
#     "KEY_ALL_ACCESS": 983103
# }

# REGISTRY_ACCESS_RIGHT = {
#     1:        "Query Value",
#     2:        "Set Value",
#     4:        "Create Subkey",
#     8:        "Enumerate Subkeys",
#     16:       "Notify",
#     32:       "Create Link",
#     65536:    "Delete",
#     131072:   "Read Control",
#     131097:   "Read",
#     262144:   "Write DAC",
#     524288:   "Write Owner",
#     983103:   "Full Control"
# }