# ADcheck
Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle, Oradad, or even PurpleKnight (with some bonuses).

ADcheck is developed in pure Python to bypass operating system constraints.

Although textual, a simple color scheme is used to navigate through the returned information (red for really bad, green for okay, white for purely informative).

It is suitable for both pentesters to facilitate research work (hopefully) and administrators concerned about the security of their environment.

At present, this tool has 74 checks and more are to come (see the [TODO](#TODO)). The collected information includes :
- [x] Number of accounts which have never expiring passwords
- [x] Admin accounts that can be delegated
- [x] Admin accounts not in Protected Users group
- [x] Number of accounts in Schema Admins group
- [x] Accounts vulnerable to asreproasting attack
- [x] Get Audit Policy
- [x] Accounts with altSecurityIdentities attributes
- [x] Accounts with userPassword attributes
- [x] Accounts with unixUserPassword attributes
- [x] Accounts with unicodePwd attributes
- [x] Accounts with msDS-HostServiceAccount attribute
- [x] Computers with bitlocker keys
- [x] Accounts with blank password
- [x] Verify if Non-admin users can add up to 10 computer(s) to a domain
- [x] Verify if User can create dns record
- [x] Computers with constrained delegation
- [x] Get Control delegations by container
- [x] Accounts which can use des authentication
- [x] Get Domain Controllers
- [x] Verify if Force logoff when logon hours expire
- [x] Get Functional level of domain
- [x] Get Group Managed Service Accounts
- [x] Get Group Policy Object by Organizational Unit
- [x] Name of Group Policy containing a password
- [x] Number of accounts with identical password
- [x] Number of inactive accounts
- [x] Accounts vulnerable to kerberoasting attack
- [x] Get Kerberos config
- [x] Get Supported Kerberos encryption algorithms
- [x] Verify if Kerberos password last changed < 40 days
- [x] Verify if LAPS is installed
- [x] Verify if LDAP signature was required on target
- [x] Locked accounts
- [x] Verify if The native administrator account has been used recently
- [x] Accounts with password not required
- [x] Get Default password policy
- [x] Get Group policy folder/file rights
- [x] Name of Pre-Windows 2000 Compatible Access group members
- [x] Get Privilege Rights (SeDebugPrivilege, SeBackupPrivilege, ...)
- [x] Get List of users in Privesc group
- [x] Get Password Settings Object
- [x] Name of Computers with rbac
- [x] Verify if Recycle Bin is enabled
- [x] Verify if MSI packages are always installed with elevated privileges
- [x] Verify if CredentialGuard is enabled
- [x] Verify if LM hash storage disabled
- [x] Verify if Authentication limited to NTLMv2 mechanism only
- [x] Verify if AppLocker rules defined
- [x] Verify if gpp_autologon is enabled
- [x] Get Name of AMSI installed
- [x] Verify if Bitlocker is enabled
- [x] Verify if Firewall is disabled
- [x] Verify if IPv4 preferred over IPv6
- [x] Verify if LLMNR, NetBIOS or mDNS is enabled
- [x] Verify if Too many logons are kept in the LSA cache
- [x] Verify if Lsass runs as a protected process
- [x] Verify if Powershell v2 is enabled
- [x] Verify if Powershell events are logged
- [x] Verify if Powershell is configured in Restricted mode
- [x] Verify if RDP use NLA
- [x] Verify if RDP is secured over pass the hash attack
- [x] Verify if RDP session timeout is too short
- [x] Verify if UAC configuration is secure
- [x] Verify if WDigest authentication enabled
- [x] Verify if WPAD is disabled
- [x] Verify if Windows Script Host is disabled
- [x] Verify if WSUS server is not used
- [x] Accounts which have reversible passwords
- [x] Get Authentication policy silos
- [x] Verify if SMB signing is required
- [x] Verify if Spooler service is enabled on remote target
- [x] Get Supported encryption by Domain Controllers
- [x] Accounts vulnerable to timeroasting attack
- [x] Name of Trust accounts for the delegation
- [x] Get Users with description
- [x] Accounts that were an admin
- [x] Verify if The computer was recently backed up
- [x] Verify if The computer is up to date

Refer to the help to see the launch options:
![alt text](https://raw.githubusercontent.com/CobblePot59/ADcheck/main/pictures/ADcheck_help.png)

# TODO
- Registry access rights
- Trusts
- Azure
- Weak certificate cipher
- Persistent attack trace(mimikatz, pywhisker, ticket, dsrm, acl)
