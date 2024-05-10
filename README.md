# ADcheck
Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle, Oradad, or even PurpleKnight (with some bonuses).

ADcheck is developed in pure Python to bypass operating system constraints.

Although textual, a simple color scheme is used to navigate through the returned information (red for really bad, green for okay, white for purely informative).

It is suitable for both pentesters to facilitate research work (hopefully) and administrators concerned about the security of their environment.

At present, this tool has 74 checks and more are to come (see the [![TODO](#TODO). The collected information includes :
- Number of accounts which have never expiring passwords
- Admin accounts that can be delegated
- Admin accounts not in Protected Users group
- Number of accounts in Schema Admins group
- Accounts vulnerable to asreproasting attack
- Get Audit Policy
- Accounts with altSecurityIdentities attributes
- Accounts with userPassword attributes
- Accounts with unixUserPassword attributes
- Accounts with unicodePwd attributes
- Accounts with msDS-HostServiceAccount attribute
- Computers with bitlocker keys
- Accounts with blank password
- Verify if Non-admin users can add up to 10 computer(s) to a domain
- Verify if User can create dns record
- Computers with constrained delegation
- Get Control delegations by container
- Accounts which can use des authentication
- Get Domain Controllers
- Verify if Force logoff when logon hours expire
- Get Functional level of domain
- Get Group Managed Service Accounts
- Get Group Policy Object by Organizational Unit
- Name of Group Policy containing a password
- Number of accounts with identical password
- Number of inactive accounts
- Accounts vulnerable to kerberoasting attack
- Get Kerberos config
- Get Supported Kerberos encryption algorithms
- Verify if Kerberos password last changed < 40 days
- Verify if LAPS is installed
- Verify if LDAP signature was required on target
- Locked accounts
- Verify if The native administrator account has been used recently
- Accounts with password not required
- Get Default password policy
- Get Group policy folder/file rights
- Name of Pre-Windows 2000 Compatible Access group members
- Get Privilege Rights (SeDebugPrivilege, SeBackupPrivilege, ...)
- Get List of users in Privesc group
- Get Password Settings Object
- Name of Computers with rbac
- Verify if Recycle Bin is enabled
- Verify if MSI packages are always installed with elevated privileges
- Verify if CredentialGuard is enabled
- Verify if LM hash storage disabled
- Verify if Authentication limited to NTLMv2 mechanism only
- Verify if AppLocker rules defined
- Verify if gpp_autologon is enabled
- Get Name of AMSI installed
- Verify if Bitlocker is enabled
- Verify if Firewall is disabled
- Verify if IPv4 preferred over IPv6
- Verify if LLMNR, NetBIOS or mDNS is enabled
- Verify if Too many logons are kept in the LSA cache
- Verify if Lsass runs as a protected process
- Verify if Powershell v2 is enabled
- Verify if Powershell events are logged
- Verify if Powershell is configured in Restricted mode
- Verify if RDP use NLA
- Verify if RDP is secured over pass the hash attack
- Verify if RDP session timeout is too short
- Verify if UAC configuration is secure
- Verify if WDigest authentication enabled
- Verify if WPAD is disabled
- Verify if Windows Script Host is disabled
- Verify if WSUS server is not used
- Accounts which have reversible passwords
- Get Authentication policy silos
- Verify if SMB signing is required
- Verify if Spooler service is enabled on remote target
- Get Supported encryption by Domain Controllers
- Accounts vulnerable to timeroasting attack
- Name of Trust accounts for the delegation
- Get Users with description
- Accounts that were an admin
- Verify if The computer was recently backed up
- Verify if The computer is up to date

Refer to the help to see the launch options:
![alt text](https://raw.githubusercontent.com/CobblePot59/ADcheck/main/pictures/ADcheck_help.png)

# TODO
- Registry access rights
- Trusts
- Azure
- Weak certificate cipher
- Persistent attack trace(mimikatz, pywhisker, ticket, dsrm, acl)
