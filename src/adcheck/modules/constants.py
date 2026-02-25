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
                ("rbcd", "Name of Computers with rbcd"),
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