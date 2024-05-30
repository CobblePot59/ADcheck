# ADcheck
Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to [PingCastle](https://github.com/vletoux/pingcastle), [ORADAD](https://github.com/ANSSI-FR/ORADAD), or even [PurpleKnight](https://www.semperis.com/fr/purple-knight/) (with some bonuses).

ADcheck is developed in pure Python to bypass operating system constraints.

Although textual, a simple color scheme is used to navigate through the returned information (🔴 red for really bad, 🟢 green for okay, ⚪ white for purely informative). A sample report is available [here](https://html-preview.github.io/?url=https://raw.githubusercontent.com/CobblePot59/ADcheck/main/report.html).

> [!NOTE]
> At present, this tool has 74 checks and more are to come (see the [TODO](#TODO)).

The collected information includes :

- [x] **Accounts**
  - [x] Admin accounts that can be delegated.
  - [x] Admin accounts not in "_Protected Users_" group.
  - [x] Accounts which can use DES authentication.
  - [x] Accounts vulnerable to ASRepRoasting attack.
  - [x] Accounts with `altSecurityIdentities` attributes.
  - [x] Accounts with `userPassword` attributes.
  - [x] Accounts with `unixUserPassword` attributes.
  - [x] Accounts with `unicodePwd` attributes.
  - [x] Accounts with `msDS-HostServiceAccount` attribute.
  - [x] Accounts with blank password.
  - [x] Accounts vulnerable to KerbeRoasting attack.
  - [x] Locked accounts.
  - [x] Number of accounts which have never expiring passwords.
  - [x] Number of accounts with identical passwords.
  - [x] Number of inactive accounts.
  - [x] Number of accounts in "_Schema Admins_" group.
  - [x] Accounts which have reversible passwords.
  - [x] Accounts vulnerable to timeroasting attack.
  - [x] Accounts that had admin rights in the past.
  - [x] Get Users with description

- [x] **Configuration**
  - [x] Get Audit Policy
  - [x] Computers with bitlocker keys
  - [x] Verify if Non-admin users can add up to 10 computer(s) to a domain
  - [x] Verify if User can create dns record
  - [x] Computers with constrained delegation
  - [x] Get Control delegations by container
  - [x] Get Domain Controllers
  - [x] Verify if Force logoff when logon hours expire
  - [x] Get Functional level of domain
  - [x] Get Group Managed Service Accounts
  - [x] Get Group Policy Object by Organizational Unit
  - [x] Name of Group Policy containing a password
  - [x] Get Kerberos config
  - [x] Get Supported Kerberos encryption algorithms
  - [x] Verify if Kerberos password last changed < 40 days
  - [x] Verify if LAPS is installed
  - [x] Verify if LDAP signature was required on target
  - [x] Verify if The native administrator account has been used recently
  - [x] Accounts with password not required
  - [x] Get Default password policy
  - [x] Get Group policy folder/file rights
  - [x] Name of Pre-Windows 2000 Compatible Access group members
  - [x] Get Privilege Rights (`SeDebugPrivilege`, `SeBackupPrivilege`, ...)
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
  - [x] Get Authentication policy silos
  - [x] Verify if SMB signing is required
  - [x] Verify if Spooler service is enabled on remote target
  - [x] Get Supported encryption by Domain Controllers
  - [x] Name of Trust accounts for the delegation
  - [x] Verify if The computer was recently backed up
  - [x] Verify if The computer is up to date

## Usage

> [!WARNING]  
> Currently, this tool is more geared towards penetration testers than auditors. If you intend to use it on Windows, it's necessary to exclude the project from the antivirus or Endpoint Detection and Response solution, as it utilizes Impacket, which is detected by these systems.

1. Clone the ADcheck repository from GitHub :
```
git clone https://github.com/CobblePot59/ADcheck.git
```

2. Navigate to the ADcheck directory :
```
cd ADcheck
```

3. Create a virtual environment :
```
python -m venv ADcheck
```

4. Activate the virtual environment (on Windows) :
```
.\ADcheck\Scripts\activate
```
(Note: On Linux/macOS, the command is **source ADcheck/bin/activate**)

5. Install dependencies from the requirements.txt file :
```
python -m pip install -r .\requirements.txt
```

6. Run the ADcheck.py script, specifying the necessary parameters :
```
python ADcheck.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1'
```
![ADcheck.gif](https://github.com/CobblePot59/ADcheck/blob/main/pictures/ADcheck.gif)

# TODO
- [ ] Registry access rights
- [ ] Trusts
- [ ] Azure (Entra ID)
- [ ] Weak certificate cipher
- [ ] Persistent attack trace (mimikatz, pywhisker, ticket, dsrm, acl)
