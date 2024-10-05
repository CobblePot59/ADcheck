from ADmanage import ADclient
from libs.impacket.smbconnection import SMBConnection, SessionError
from modules.MSuacCalc import uac_details
from modules.MSaceCalc import SecurityDescriptorParser
from modules.decor import admin_required, capture_stdout
from modules.constants import WELL_KNOWN_SIDS, SUPPORTED_ENCRYPTION
from termcolor import colored
from datetime import datetime, timezone
from pathlib import Path
import dns.resolver
import json
import re


class ADcheck:
    def __init__(self, domain, username, password, hashes, dc_ip, options=None):
        self.domain = domain
        self.base_dn = f"DC={domain.split('.')[0]},DC={domain.split('.')[1]}"
        self.username = username
        self.password = password
        self.hashes = hashes
        self.nthash = hashes.split(':')[1] if hashes else ''
        self.dc_ip = dc_ip
        self.secure = options.secure
        self.output = options.output
        self.is_admin = options.is_admin

        self.connect()

    def connect(self):
        from modules.RegReader import RegReader
        from modules.WMIquery import WMIquery
        import asyncio


        self.ad_client = ADclient(domain=self.domain, username=self.username, password=self.password, hashes=self.hashes, dc_ip=self.dc_ip, base_dn=self.base_dn, secure=self.secure, anonymous=False)
        self.smb_client = SMBConnection(self.dc_ip, self.dc_ip)
        self.smb_client.login(self.username, self.password, self.domain, nthash=self.nthash)
        self.reg_client = lambda key, subKey=False: RegReader(self.dc_ip, self.username, self.password, self.domain, self.nthash, key, subKey).run()
        self.wmi_client = lambda query, namespace='root/cimv2': asyncio.run(WMIquery(self.dc_ip, self.username, self.password, self.domain, query, namespace).run())

        self.update_entries()

    def update_entries(self):
        self.all_entries = self.ad_client.get_ADobjects(custom_filter='(objectClass=*)')
        self.user_entries = self.ad_client.get_ADobjects(custom_filter='(&(objectClass=user)(!(objectClass=computer)))')
        self.computer_entries = self.ad_client.get_ADobjects(custom_filter='(objectClass=computer)')
        self.policies_entries = [entry for entry in self.ad_client.get_ADobjects(custom_filter='(objectClass=groupPolicyContainer)') if 'displayName' in entry]
        self.root_entry = [domain for domain in self.ad_client.get_ADobjects(custom_filter='(objectClass=domain)') if domain['distinguishedName'] == self.base_dn][0]
        self.schema_objects = self.ad_client.get_ADobjects(custom_base_dn=f'CN=Schema,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=classSchema)')
        self.schema_attributes = self.ad_client.get_ADobjects(custom_base_dn=f'CN=Schema,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=attributeSchema)')
        self.extended_rights = self.ad_client.get_ADobjects(custom_base_dn=f'CN=Extended-Rights,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=controlAccessRight)')
        self.domain_sid = self.domain_controlers(_return=True)[0]['objectSid'][:41]
        self.NEW_WELL_KNOWN_SIDS = {key.replace('domain-', self.domain_sid): value for key, value in WELL_KNOWN_SIDS.items()}

    def pprint(self, result, message, reverse=False):
        color = 'black' if result == 'INFO' else ('red' if (result and not reverse) or (not result and reverse) else 'green')
        html = f'<span style="color:{color};">{message}</span>\n'
        if result == 'INFO':
            print(message)
            if self.output:
                with open('report.html', 'a') as report:
                    report.write(html)
        else:
            print(colored(message, color))
            if self.output:
                with open('report.html', 'a') as report:
                    report.write(html)

    def domain_controlers(self, _return=False):
        result = []
        for computer in self.computer_entries:
            if 'SERVER_TRUST_ACCOUNT' in uac_details(computer['userAccountControl']):
                result.append(computer)

        result2 = [dc['sAMAccountName'] for dc in result]
        if _return:
            return result 
        else:
            self.pprint('INFO', f'Domain Controllers: {result2}')

    def can_add_computer(self):
        result = self.root_entry['ms-DS-MachineAccountQuota']
        self.pprint(result, f'Non-admin users can add up to {result} computer(s) to a domain')

    def accounts_never_expire(self):
        password_unexpire = []
        for user in self.user_entries:
            if 'DONT_EXPIRE_PASSWORD' in uac_details(user['userAccountControl']):
                password_unexpire.append(user['sAMAccountName'])
        
        result = False
        if len(password_unexpire) > 50:
            result = True
        self.pprint(result, f'Number of accounts which have never expiring passwords : {len(password_unexpire)}')

    def native_admin_logon(self):
        for user in self.user_entries:
            if user['objectSid'] == f'{self.domain_sid.rstrip("-")}-500':
                admin_lastLogon = user['lastLogon']
        admin_lastLogon_date = datetime.strptime(str(admin_lastLogon), '%Y-%m-%d %H:%M:%S.%f%z').date()
        ndays = (datetime.now().date() - admin_lastLogon_date).days

        result = False
        if ndays < 30:
            result = True
        self.pprint(result, f'The native administrator account has been used recently : {ndays} day(s) ago')

    def admin_can_be_delegated(self):
        result = []
        for user in self.user_entries:
            if 'adminCount' in user and user['cn'] != 'krbtgt' and 'NOT_DELEGATED' not in uac_details(user['userAccountControl']):
                result.append(user['sAMAccountName'])
        self.pprint(result, f'Admin accounts that can be delegated : {result}')

    def admins_schema(self):
        result = self.ad_client.get_member('Schema Admins')
        self.pprint(result, f'Accounts in Schema Admins group : {result}')

    def admin_not_protected(self):
        result = []
        for user in self.user_entries:
            if 'adminCount' in user and 'memberOf' in user and user['cn'] != 'krbtgt':
                is_protected_user = False
                for group in user['memberOf']:
                    if 'CN=Protected Users' in group:
                        is_protected_user = True
                        break
                if not is_protected_user:
                    result.append(user['sAMAccountName'])
        self.pprint(result, f'Admin accounts not in Protected Users group : {result}')

    def ldap_signing(self):
        from ldap3.core.exceptions import LDAPBindError

        try:
            ADclient(domain=self.domain, username=self.username, password=self.password, hashes=self.hashes, dc_ip=self.dc_ip, base_dn=self.base_dn, secure=False, anonymous=False)
            self.pprint(True, f'LDAP signature was required on target : False')
        except LDAPBindError as e:
            if 'strongerAuthRequired:' in str(e):
                self.pprint(False, f'LDAP signature was required on target : True')

    def pre2000_group(self):
        group_entries = self.ad_client.get_ADobjects(custom_filter='(objectClass=group)')
        for group in group_entries:
            if group['objectSid'] == 'S-1-5-32-554':
                members = self.ad_client.get_member(group['name'])

        result = False
        if isinstance(members, str) and 'S-1-5-11' in members:
                result = True
        elif isinstance(members, list):
            for user in members:
                if 'S-1-5-11' in user:
                    result = True
        self.pprint(result, f'Pre-Windows 2000 Compatible Access group members contain "Authenticated Users : {result}')

    def privesc_group(self):
        from modules.constants import PRIVESC_GROUP

        result = {}
        for group in PRIVESC_GROUP:
            member = self.ad_client.get_member(group)
            if member:
                if isinstance(member, list):
                    result[group] = list(self.ad_client.get_member(group))
                else:
                    result[group] = ''.join(self.ad_client.get_member(group))
            else:
                result[group] = []
        self.pprint('INFO', f'Privesc group :\n{json.dumps(result, indent=4)}')

    def krbtgt_password_age(self):
        krbtgt_pwdLastSet = self.ad_client.get_ADobject('krbtgt')['pwdLastSet']
        krbtgt_pwdLastSet_date = datetime.strptime(str(krbtgt_pwdLastSet), '%Y-%m-%d %H:%M:%S.%f%z').date()
        ndays = (datetime.now().date() - krbtgt_pwdLastSet_date).days

        result = False
        if ndays > 40:
            result = True
        self.pprint(result, f'Kerberos password last changed : {ndays} day(s) ago')

    def spooler(self):
        from libs.impacket.dcerpc.v5 import transport, rprn

        rpctransport = transport.DCERPCTransportFactory(rf'ncacn_np:{self.dc_ip}[\pipe\spoolss]')
        rpctransport.set_credentials(self.username, self.password, self.domain, nthash=self.nthash)
        dce = rpctransport.get_dce_rpc()

        try:
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            self.pprint(True, 'Spooler service is enabled on remote target : True')
        except Exception as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                message = 'Access denied'
            elif 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                message = 'Spooler service is enabled on remote target: False'
            else:
                message = f'Unhandled exception occurred: {e}'
            self.pprint(False, message)

    def reversible_password(self):
        result = []
        for user in self.user_entries:
            if 'ENCRYPTED_TEXT_PASSWORD_ALLOWED' in uac_details(user['userAccountControl']):
                result.append(user['sAMAccountName'])
        self.pprint(result, f'Accounts which have reversible passwords : {result}')

    def inactive_accounts(self):
        result = []
        for user in self.user_entries:
            if 'lastLogon' not in user:
                continue
                
            user_lastLogon = str(user['lastLogon'])
            if user_lastLogon == '1601-01-01 00:00:00+00:00':
                continue

            user_lastLogon_date = datetime.strptime(user_lastLogon, '%Y-%m-%d %H:%M:%S.%f%z').date()
            ndays = (datetime.now().date() - user_lastLogon_date).days
            if ndays >= 90:
                result.append(user['sAMAccountName'])
        self.pprint(result, f'Number of inactive accounts: {len(result)}')

    def locked_accounts(self):
        naccounts = []
        for user in self.user_entries:
            if 'LOCKOUT' in uac_details(user['userAccountControl']):
                naccounts.append(user['sAMAccountName'])
        result = False
        if len(naccounts) > 5:
            result = True
        self.pprint(result, f'Locked accounts : {naccounts}')

    def des_authentication(self):
        result = []
        for user in self.user_entries:
            if 'USE_DES_KEY_ONLY' in uac_details(user['userAccountControl']):
                result.append(user['sAMAccountName'])
        self.pprint(result, f'Accounts which can use des authentication : {result}')

    def asreproast(self):
        result = []
        for user in self.user_entries:
            if 'DONT_REQ_PREAUTH' in uac_details(user['userAccountControl']):
                result.append(user['sAMAccountName'])
        self.pprint(result, f'Accounts vulnerable to asreproasting attack : {result}')

    def kerberoast(self):
        result = []
        for user in self.user_entries:
            if 'servicePrincipalName' in user and user['cn'] != 'krbtgt':
                result.append(user['sAMAccountName'])
        self.pprint(result, f'Accounts vulnerable to kerberoasting attack : {result}')

    def trusted_for_delegation(self):
        users = []
        for user in self.user_entries:
            if 'TRUSTED_FOR_DELEGATION' in uac_details(user['userAccountControl']):
                users.append(user['sAMAccountName'])

        computers = []
        for computer in self.computer_entries:
            if 'TRUSTED_FOR_DELEGATION' in uac_details(computer['userAccountControl']) and not 'SERVER_TRUST_ACCOUNT'  in uac_details(computer['userAccountControl']):
                computers.append(computer['sAMAccountName'])

        result = users + computers
        self.pprint(result, f'Trust accounts for the delegation : {result}')

    def password_not_required(self):
        result = []
        for user in self.user_entries:
            if 'PASSWD_NOTREQD' in uac_details(user['userAccountControl']):
                if user['sAMAccountName'] != 'Guest':
                    result.append(user['sAMAccountName'])
        self.pprint(result, f'Accounts with password not required : {result}')

    @admin_required
    def ntds_dump(self):
        @capture_stdout
        def ntlm_hashes(dc_ip, username, password, domain, nthash):
            from modules.SmallSecretsDump import DumpSecrets

            DumpSecrets(dc_ip, username, password, domain, nthash).dump()
        return ntlm_hashes(self.dc_ip, self.username, self.password, self.domain, self.nthash).strip().split('\n')
    
    @admin_required
    def identical_password(self):
        hashes = [line.split(':')[3] for line in self.ntds_dump()]
        hash_counts = {hash: hashes.count(hash) for hash in hashes}
        duplicate_counts = sum(count for count in hash_counts.values() if count > 1)

        result = 0
        for cpt in hash_counts.values():
            if cpt > 1:
                result += 1
        self.pprint(result, f'Number of accounts with identical password : {result}')

    @admin_required
    def blank_password(self):
        result = []
        for line in self.ntds_dump():
            _hash = line.split(':')[3]
            user = line.split(':')[0]

            if  _hash == '31d6cfe0d16ae931b73c59d7e0c089c0' and  user != 'Guest':
                result.append(user)
        self.pprint(result, f'Accounts with blank password : {result}')

    def was_admin(self):
        result = []
        for user in self.user_entries:
            if 'adminCount' in user and user['cn'] != 'krbtgt' and user['objectSid'] != 'S-1-5-32-544':
                result.append(user['sAMAccountName'])
        self.pprint(result, f'Accounts that were an admin : {result}')

    def gpo_by_ou(self):
        policies = [{'name': policy['name'], 'displayName': policy['displayName']} for policy in self.policies_entries]
        
        groups = []
        for entry in self.all_entries:
            if 'gPLink' in entry:
                groups.append({'dn': entry['distinguishedName'], 'name': re.findall(r'{(.*?)}', entry['gPLink'])})

        result = []
        for group in groups:
            group_result = {'dn': group['dn'], 'gpLink': []}
            for name in group['name']:
                for policy in policies:
                    if policy['name'] == f'{{{name}}}':
                        group_result['gpLink'].append({'name': policy['name'], 'displayName': policy['displayName']})
            result.append(group_result)
        self.pprint('INFO', f'Group Policy Object by Organizational Unit :\n{json.dumps(result, indent=4)}')

    def get_policies(self):
        from modules.GPOBrowser import smb_download

        smb_download(self.smb_client, f'{self.domain}/Policies', 'GPOS')

    def smb_signing(self):
        result = False
        if self.smb_client.isSigningRequired():
            result = True
        self.pprint(result, f'SMB signing is required : {result}', reverse=True)

    def password_policy(self):
        from modules.constants import PWD_PROPERTIES
        
        result = {
                    'lockoutDuration': str(self.root_entry['lockoutDuration']),
                    'lockOutObservationWindow': str(self.root_entry['lockOutObservationWindow']),
                    'maxPwdAge': self.root_entry['maxPwdAge'],
                    'minPwdAge': self.root_entry['minPwdAge'],
                    'minPwdLength': self.root_entry['minPwdLength'],
                    'pwdHistoryLength': self.root_entry['pwdHistoryLength'],
                    'pwdProperties': PWD_PROPERTIES.get(int(self.root_entry['pwdProperties']))
                }
        self.pprint('INFO', f'Default password policy :\n{json.dumps(result, indent=4)}')

    def functional_level(self):
        from modules.constants import FOREST_LEVELS

        result = FOREST_LEVELS.get(int(self.root_entry['msDS-Behavior-Version']))
        self.pprint('INFO', f'Functional level of domain is : {result}')

    def force_logoff(self):
        result = False
        if self.root_entry['forceLogoff'] == 0:
            result = True
        self.pprint(result, f'Force logoff when logon hours expire : {result}', reverse=True)

    def can_update_dns(self):
        result = False
        try:
            if self.ad_client.add_DNSentry('adcheck', '7.7.7.7'):
                result = True
            self.ad_client.del_DNSentry('adcheck')
        except dns.resolver.NoResolverConfiguration:
            self.pprint('Error: No DNS resolver is configured.')
            return
        self.pprint(result, f'User can create dns record : {result}')

    def auth_attributes(self):
        attributes = ['altSecurityIdentities', 'userPassword', 'unixUserPassword', 'unicodePwd', 'msDS-HostServiceAccount']
        users_attribute = {}
        for attribute in attributes:
            users_attribute[attribute] = []
            for user in self.user_entries:
                if attribute in user:
                    users_attribute[attribute].append(user['sAMAccountName'])
        for attribute, result in users_attribute.items():
            self.pprint(result, f'Accounts with {attribute} attributes: {result}')
    
    @admin_required
    def laps(self):
        try:
            self.smb_client.listPath('C$', 'Program Files\\LAPS\\AdmPwd.Utils.dll')
            self.pprint(False, f'LAPS legacy is installed : True')
        except Exception as e:
            result = False
            for computer in self.computer_entries:
                if 'msLAPS-PasswordExpirationTime' in computer:
                    result = True
                    break
            self.pprint(result, f'LAPS is installed : {result}', reverse=True)

    def pso(self):        
        pso = self.ad_client.get_ADobjects(custom_filter='(objectClass=msDS-PasswordSettings)')

        result = []
        if pso:
            for i in range(len(pso)):
                result.append(
                    {
                        pso[i]['name']: {
                            'lockoutDuration': abs(float(pso[i]['msDS-LockoutDuration'])) / 600000000,
                            'lockOutObservationWindow': abs(float(pso[i]['msDS-LockoutObservationWindow'])) / 600000000,
                            'lockoutThreshold': pso[i]['msDS-LockoutThreshold'],
                            'maxPwdAge': abs(float(pso[i]['msDS-MaximumPasswordAge']) / (10**7 * 60 * 60 * 24)),
                            'minPwdAge': abs(float(pso[i]['msDS-MinimumPasswordAge']) / (10**7 * 60 * 60 * 24)),
                            'minPwdLength': pso[i]['msDS-MinimumPasswordLength'],
                            'psoAppliesTo': pso[i]['msDS-PSOAppliesTo'],
                            'pwdComplexity': pso[i]['msDS-PasswordComplexityEnabled'],
                            'pwdHistoryLength': pso[i]['msDS-PasswordHistoryLength'],
                            'pwdReversibleEncryption': pso[i]['msDS-PasswordReversibleEncryptionEnabled'],
                            'pwdSettingsPrecedence': pso[i]['msDS-PasswordSettingsPrecedence'],
                        }
                    }
                )
        self.pprint('INFO', f'Password Settings Object :\n{json.dumps(result, indent=4)}')

    def supported_encryption(self):
        result = [f"{dc['sAMAccountName']}: [{SUPPORTED_ENCRYPTION.get(int(dc['msDS-SupportedEncryptionTypes']))}]" for dc in self.domain_controlers(_return=True)]
        self.pprint('INFO', f'Supported encryption by Domain Controllers :\n{json.dumps(result, indent=4)}')

    def constrained_delegation(self):
        result = []
        for computer in self.computer_entries:
            if 'msDS-AllowedToDelegateTo' in computer:
                result.append(f"{computer['sAMAccountName']}: {computer['msDS-AllowedToDelegateTo']}")
        self.pprint(result, f'Computers with constrained delegation :\n{json.dumps(result, indent=4)}')

    def rbac(self):
        result = []
        for computer in self.computer_entries:
            if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in computer:
                result.append(computer['sAMAccountName'])
        self.pprint(result, f'Computers with rbac :{result}')

    def gMSA(self):
        gMSAs = self.ad_client.get_ADobjects(custom_filter='(objectClass=msDS-GroupManagedServiceAccount)')

        result = []
        if gMSAs:
             for gMSA in gMSAs:
                result.append({'dn': gMSA['distinguishedName'], 'msDS-HostServiceAccountBL': gMSA['msDS-HostServiceAccountBL'], 'msDS-ManagedPasswordInterval': gMSA['msDS-ManagedPasswordInterval']})
        self.pprint('INFO', f'Group Managed Service Accounts :\n{json.dumps(result, indent=4)}')

    def silos(self):
        authn_container = self.ad_client.get_ADobjects(custom_base_dn=f'CN=AuthN Policy Configuration,CN=Services,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=*)')

        authn_policies = []
        for policy in authn_container:
            if 'msDS-AuthNPolicyEnforced' in policy:
                authn_policies.append(policy)

        authn_silos = []
        for policy in authn_container:
            if 'msDS-AuthNPolicySiloEnforced' in policy:
                authn_silos.append(policy)
        
        authn_policy_dict = {authn_policy['distinguishedName']: authn_policy for authn_policy in authn_policies}

        result = []
        for authn_silo in authn_silos:
            result.append(
                {
                    'name': authn_silo['name'],
                    'AuthNPolicySiloEnforced': authn_silo['msDS-AuthNPolicySiloEnforced'],
                    'AuthNPolicySiloMembers': authn_silo['msDS-AuthNPolicySiloMembers'],
                    'ComputerAuthNPolicy': {
                        'name': authn_policy_dict[authn_silo['msDS-ComputerAuthNPolicy']]['name'],
                        'ComputerTGTLifetime': float(authn_policy_dict[authn_silo['msDS-ComputerAuthNPolicy']]['msDS-ComputerTGTLifetime']) / 600000000,
                    },
                    'ServiceAuthNPolicy': {
                        'name': authn_policy_dict[authn_silo['msDS-ServiceAuthNPolicy']]['name'],
                        'ServiceAllowedNTLMNetworkAuthentication': authn_policy_dict[authn_silo['msDS-ServiceAuthNPolicy']]['msDS-ServiceAllowedNTLMNetworkAuthentication'],
                        'ServiceTGTLifetime': float(authn_policy_dict[authn_silo['msDS-ServiceAuthNPolicy']]['msDS-ServiceTGTLifetime']) / 600000000,
                    },
                    'UserAuthNPolicy': {
                        'name': authn_policy_dict[authn_silo['msDS-UserAuthNPolicy']]['name'],
                        'StrongNTLMPolicy': authn_policy_dict[authn_silo['msDS-UserAuthNPolicy']]['msDS-StrongNTLMPolicy'],
                        'UserAllowedNTLMNetworkAuthentication': authn_policy_dict[authn_silo['msDS-UserAuthNPolicy']]['msDS-UserAllowedNTLMNetworkAuthentication'],
                        'UserTGTLifetime': float(authn_policy_dict[authn_silo['msDS-UserAuthNPolicy']]['msDS-UserTGTLifetime']) / 600000000,
                    }
                }   
            )
        self.pprint('INFO', f'Authentication policy silos :\n{json.dumps(result, indent=4)}')

    def recycle_bin(self):
        result = True if 'msDS-EnabledFeatureBL' in self.ad_client.get_ADobjects(custom_base_dn=f'CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=*)')[0] else False
        self.pprint(result, f'Recycle Bin is enabled : {result}', reverse=True)

    @admin_required
    def control_delegations(self):
        self.pprint('INFO', 'Control delegations :')
        ous_object = self.ad_client.get_ADobjects(custom_filter='(objectClass=organizationalUnit)', custom_attributes=['distinguishedName', 'nTSecurityDescriptor'])
        containers_name = [f'CN=Computers,{self.base_dn}', f'CN=ForeignSecurityPrincipals,{self.base_dn}', f'CN=Keys,{self.base_dn}', f'CN=Managed Service Accounts,{self.base_dn}', f'CN=Program Data,{self.base_dn}', f'CN=Users,{self.base_dn}']
        containers_object = [self.ad_client.get_ADobjects(custom_base_dn=container,custom_filter='(objectClass=container)', custom_attributes=['distinguishedName', 'nTSecurityDescriptor'])[0] for container in containers_name]
        domains_object = self.ad_client.get_ADobjects(custom_filter='(objectClass=Domain)', custom_attributes=['distinguishedName', 'nTSecurityDescriptor'])

        containers =  ous_object + containers_object + domains_object
        parser = SecurityDescriptorParser(self.NEW_WELL_KNOWN_SIDS, self.schema_objects, self.schema_attributes, self.extended_rights, self.all_entries, 'container')
        result = parser.process_containers(containers)
        self.pprint('INFO', f'{json.dumps(result, indent=4)}\n')

    def krbtgt_encryption(self):
        result = SUPPORTED_ENCRYPTION.get(int(self.ad_client.get_ADobject('krbtgt')['msDS-SupportedEncryptionTypes']))
        self.pprint('INFO', f'Supported Kerberos encryption algorithms : {result}')

    def bitlocker(self):
        recovery_information = self.ad_client.get_ADobjects(custom_filter='(objectClass=msFVE-RecoveryInformation)')
        result = []
        if recovery_information:
            for computer in recovery_information:
                result.append(str(computer['distinguishedName']).split(','))
        self.pprint('INFO', f'Computers with bitlocker keys : {result}')

    def gpp_password(self):
        result = []
        for file_path in Path('GPOS').rglob('*.xml'):
            for line in open(file_path):
                if 'cpassword' in line:
                    entry = Path(file_path).parts[1]
                    for policy in self.policies_entries:
                        if entry == policy['cn']:
                            result.append(policy['displayName'])
        self.pprint(result, f'Group Policy containing a password : {result}')

    def timeroast(self):
        computers_noLogonCount = [computer['sAMAccountName'] for computer in self.ad_client.get_ADobjects(custom_filter='(&(userAccountControl=4128)(logonCount=0))') or []]
        result = []
        for computer in computers_noLogonCount:
            try:
                SMBConnection(self.dc_ip, self.dc_ip).login(computer, computer.lower().replace('$', ''), self.domain)
            except SessionError as e:
                if 'STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT' in str(e):
                    result.append(computer)
        self.pprint(result, f'Accounts vulnerable to timeroasting attack : {result}')

    def kerberos_hardened(self):
        result = {}
        for file_path in Path('GPOS').rglob('*.inf'):
            for line in open(file_path, encoding='utf-16'):
                match = re.match(r"(MaxTicketAge|MaxRenewAge|MaxServiceAge|MaxClockSkew|TicketValidateClient)\s*=\s*(\d+)", line)
                if match:
                    result[match.group(1)] = match.group(2)
        self.pprint('INFO', f'Kerberos config :\n{json.dumps(result, indent=4)}')

    @admin_required
    def audit_policy(self):
        from csv import DictReader

        try:
            tree_id = self.smb_client.connectTree('C$')
            file = self.smb_client.openFile(tree_id, 'Windows\\System32\\GroupPolicy\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv')
            file_content = self.smb_client.readFile(tree_id, file)
            self.smb_client.disconnectTree(tree_id)

            
            csv_reader = DictReader(file_content.decode('utf-8').splitlines())
            result = [{'Subcategories': row['Subcategory'], 'Inclusion Settings': row['Inclusion Setting']} for row in csv_reader]
            self.pprint('INFO', f'Audit policy configured : \n{json.dumps(result, indent=4)}')
        except SessionError as e:
            if 'STATUS_OBJECT_PATH_NOT_FOUND' in str(e):
                self.pprint(True, 'Audit policy not configured')
        
    def priv_rights(self):
        gpo_content = []
        for file_path in Path('GPOS').rglob('*.inf'):
            with open(file_path, encoding='utf-16') as file:
                file_content = file.read()
            match = re.search(r'\[Privilege Rights\](.*?)(\[\w+|\Z)', file_content, re.DOTALL)
            if match:
                content = match.group(1).strip()
                gpo_content.append(content)

        result = {}
        for lines in gpo_content:
            for line in lines.strip().split('\n'):
                parts = line.split('=')
                key = parts[0].strip()
                values = []
                for sid in parts[1].split(','):
                    sid = sid.strip().strip('*')
                    value = self.NEW_WELL_KNOWN_SIDS.get(sid, sid)
                    values.append(value)
                result[key] = values
        self.pprint('INFO', f'Privilege Rights :\n{json.dumps(result, indent=4)}')

    def policies_ace(self):
        from modules.GPOBrowser import smb_get_attributes
        from modules.constants import FILE_ACCESS_RIGHT, DIRECTORY_ACCESS_RIGHT

        gpo_path_rights = smb_get_attributes(self.smb_client, f'{self.domain}/Policies')
        policies = [{'name': policy['name'], 'displayName': policy['displayName']} for policy in self.policies_entries]

        parents = {}
        for item in gpo_path_rights:
            if item['is_parent']:
                parents[item['path']] = item['rights']

        result = {}
        for parent_path, parent_rights in parents.items():
            childs = []
            for item in gpo_path_rights:
                if not item['is_parent'] and item['path'].startswith(parent_path):
                    childs.append((item['path'], item['rights'], item['is_directory']))

            child_results = set()
            for child_path, child_rights, child_directory in childs:
                if child_directory and (child_rights != parent_rights):
                    child_result = f"User can {DIRECTORY_ACCESS_RIGHT.get(child_rights)} {child_path}"
                elif not child_directory:
                    child_result = f"User can {DIRECTORY_ACCESS_RIGHT.get(child_rights)} {child_path}"
                child_results.add(child_result)

            parent_policy_path = parent_path.split(f'{self.domain}/Policies/')[1]
            for policy in policies:
                if policy['name'] == parent_policy_path:
                    parent_policy_name = policy['displayName']
                    break

            result[f"User can {DIRECTORY_ACCESS_RIGHT.get(parent_rights)} {parent_policy_name}"] = list(child_results)
        self.pprint('INFO', f'Group policy folder/file rights :\n{json.dumps(result, indent=4)}')

    def users_description(self):
        result = []
        for user in self.user_entries:
            if 'description' in user and not self.NEW_WELL_KNOWN_SIDS.get(user['objectSid']):
                result.append(user['sAMAccountName'])
        self.pprint('INFO', f'Users with description : {result}')

    def bloodhound_file(self):
        from libs.bloodhound import BloodHound, ADAuthentication
        from libs.bloodhound.ad.domain import AD
        from time import time

        auth = ADAuthentication(username=self.username, password=self.password, domain=self.domain, auth_method='auto')
        if self.hashes:
            lm, nt = self.hashes.split(":")
            auth = ADAuthentication(lm_hash=lm, nt_hash=nt, username=self.username, domain=self.domain, auth_method='auto')
        try:
            ad = AD(auth=auth, domain=self.domain, nameserver=self.dc_ip, dns_tcp=False, dns_timeout=3, use_ldaps=self.secure)
            ad.dns_resolve(domain=self.domain)
        except dns.resolver.NoResolverConfiguration:
            print("Error: No DNS resolver is configured.")
            return

        bloodhound = BloodHound(ad)
        bloodhound.connect()

        collect = ['group', 'localadmin', 'session', 'trusts', 'objectprops', 'acl', 'dcom', 'rdp', 'psremote', 'container']
        timestamp = datetime.fromtimestamp(time()).strftime('%Y%m%d%H%M%S') + '_'
        bloodhound.run(collect=collect, num_workers=10, disable_pooling=True, timestamp=timestamp, computerfile='', cachefile=None, exclude_dcs=False, fileNamePrefix='')

    def namedpipes(self):
        result = [pipe.get_longname() for pipe in self.smb_client.listPath('IPC$', r'\\*')]
        self.pprint('INFO', f'Named Pipes :\n{json.dumps(result, indent=4)}')
    
    def ldap_anonymous(self):
        ad_client = ADclient(domain=self.domain, dc_ip=self.dc_ip, anonymous=True)
        result = ad_client.conn.bind()
        self.pprint(result, f'Ldap anonymous bind : {result}')

    @admin_required
    def wmi_last_update(self):
        # https://github.com/netinvent/windows_tools/blob/master/windows_tools/updates/__init__.py#L144
        hotfix_list = self.wmi_client('SELECT Description, HotFixID, InstalledOn FROM Win32_QuickFixEngineering')
        last_update = max(hotfix_list, key=lambda x: x['InstalledOn'])['InstalledOn']
        last_update_date = datetime.strptime(last_update, "%m/%d/%Y")
        ndays = (datetime.now() - last_update_date).days

        result = ndays < 30
        self.pprint(result, f'The computer is up to date (Last : {last_update}) : {result}', reverse=True)

    @admin_required
    def wmi_last_backup(self):
        events = self.wmi_client("SELECT * FROM Win32_NTLogEvent WHERE LogFile='Directory Service' AND EventCode=1917")
        if events:
            last_backup = max(events, key=lambda x: x['TimeWritten'])['TimeWritten']
            ndays = (datetime.now(timezone.utc) - last_backup).days
            result = ndays < 1
            self.pprint(result, f'The computer was recently backed up (Last : {last_backup}) : {result}', reverse=True)
        else:
            self.pprint(True, 'The computer was never backed up')

    @admin_required
    def reg_ace(self):
        from modules.RegReader import RegReader

        parser = SecurityDescriptorParser(self.NEW_WELL_KNOWN_SIDS, self.schema_objects, self.schema_attributes, self.extended_rights, self.all_entries, 'reg_key')
        reg_keys = ['HKLM\\SYSTEM', 'HKLM\\SECURITY', 'HKLM\\SAM']
        for reg_key in reg_keys:
            reg_client = RegReader(self.dc_ip, self.username, self.password, self.domain, self.nthash, reg_key)
            security_descriptor = reg_client.get_security_descriptor()
            result = parser.process_regKeys(security_descriptor)
            self.pprint('INFO', f'{reg_key} permissions :')
            self.pprint('INFO', f'{json.dumps(result, indent=4)}\n')

    @admin_required
    def reg_ca(self):
        import requests
        from io import StringIO
        from csv import DictReader
        import OpenSSL.crypto
        import binascii
        

        key_types = {6: 'TYPE_RSA', 10: 'TYPE_DSA', 16: 'TYPE_DH', 408: 'TYPE_EC', 480: 'TYPE_SM2'}
        
        # Get the list of trusted CAs
        response = requests.get('https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV')
        trusted_ca = {row['SHA-256 Fingerprint']: row for row in DictReader(StringIO(response.text))}

        untrusted_ca = []
        disabled_certificates = []
        
        # Get local certificates
        ca_paths = ['AuthRoot', 'ROOT']
        for ca_path in ca_paths:
            subkeys = self.reg_client(f'HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\{ca_path}\\Certificates\\', subKey=True)
            for subkey in subkeys:
                for value in subkey.values():
                    blob = binascii.unhexlify(value[0]['Blob'])
                    der_start = blob.find(b'\x30\x82') # Start of ASN.1 sequence
                    try:
                        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, blob[der_start:])
                    except OpenSSL.crypto.Error as e:
                        print(f"Error loading certificate: {e}")
                        continue

                    cert_info = {
                        'Issuer': ', '.join([f"{key.decode('utf-8')}:{value.decode('utf-8')}" for key, value in cert.get_issuer().get_components()]),
                        'Subject': ', '.join([f"{key.decode('utf-8')}:{value.decode('utf-8')}" for key, value in cert.get_issuer().get_components()]),
                        'Version': cert.get_version(),
                        'Not Before': cert.get_notBefore().decode('utf-8'),
                        'Not After': cert.get_notAfter().decode('utf-8'),
                        'Serial Number': cert.get_serial_number(),
                        'Signature Algorithm': cert.get_signature_algorithm().decode('utf-8'),
                        'Public Key': f'type: {key_types[cert.get_pubkey().type()]}, bits: {cert.get_pubkey().bits()}',
                        'Digest': cert.digest("sha256").decode('utf-8').replace(':', ''),
                        'Extensions': [cert.get_extension(i).get_short_name().decode('utf-8') for i in range(cert.get_extension_count())]
                    }

                    # Check CA status
                    if cert_info['Digest'] not in trusted_ca:
                        untrusted_ca.append({ca_path : cert_info})
                    elif trusted_ca[cert_info['Digest']]['Microsoft Status'] == 'Disabled':
                        disabled_certificates.append({ca_path : cert_info})

        self.pprint(untrusted_ca, f'Untrusted Certificates : {json.dumps(untrusted_ca, indent=4)}')
        self.pprint(disabled_certificates, f'\nDisabled Certificates : {json.dumps(disabled_certificates, indent=4)}')

    @admin_required
    def reg_uac(self):
        hives = {
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA': 1,
            # 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy': 0
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'UAC configuration is secure : {result}', reverse=True)

    @admin_required
    def reg_LMHASH(self):
        hives = {
            'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash': 1
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'LM hash storage disabled : {result}', reverse=True)

    @admin_required
    def reg_NTLMv2(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel': 5
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'Authentication limited to NTLMv2 mechanism only : {result}', reverse=True)

    @admin_required
    def reg_AlwaysInstallElevated(self):
        hives = {
            'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated': 1
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'MSI packages are always installed with elevated privileges : {result}')

    @admin_required
    def reg_ipv4_only(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisabledComponents': 128
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'IPv4 preferred over IPv6 : {result}', reverse=True)

    @admin_required
    def reg_wdigest(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential': 1
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'WDigest authentication enabled : {result}')

    @admin_required
    def reg_lsa_cache(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount': 2
        }
        try:
            result = all(int(self.reg_client(key).replace('\x00', '')) >= hives.get(key) for key in hives)
            self.pprint(result, f'Too many logons are kept in the LSA cache : {result}')
        except AttributeError :
            self.pprint(True, 'LSA cache length is not defined')

    @admin_required
    def reg_wsus_config(self):
        hives = {
            'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer': 'https://'
        }
        try:
            result = all(self.reg_client(key).startswith(hives.get(key)) for key in hives)
            self.pprint(result, f'WSUS configuration is secure : {result}', reverse=True)
        except AttributeError :
            self.pprint(True, 'WSUS server is not used')

    @admin_required
    def reg_rdp_timeout(self):
        hives = {
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\MaxDisconnectionTime': 0,
            'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\MaxDisconnectionTime': 0
        }
        try:
            result = any(self.reg_client(key) <= hives.get(key) for key in hives)
            self.pprint(result, f'RDP session timeout is too short : {result}')
        except:
            self.pprint(True, 'RDP session timeout is not defined')

    @admin_required
    def reg_CredentialGuard(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity': 1,
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags': 1
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'CredentialGuard is enabled : {result}', reverse=True)

    @admin_required
    def reg_lsass_ppl(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL': '1'
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'Lsass runs as a protected process : {result}', reverse=True)

    @admin_required
    def reg_pwsh2(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine\\PSCompatibleVersion': '2.0'
        }
        result = all(hives.get(key) in self.reg_client(key) for key in hives)
        self.pprint(result, f'Powershell v2 is enabled : {result}')

    @admin_required
    def reg_rdp_nla(self):
        hives = {
            'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication': 1
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'RDP use NLA : {result}', reverse=True)

    @admin_required
    def reg_rdp_nopth(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\DisableRestrictedAdmin': 0,
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictedAdminMode': 1,
            'HKLM\\Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation': 1
        }
        result = any(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'RDP is secured over pass the hash attack : {result}', reverse=True)

    @admin_required
    def reg_pwsh_restricted(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell\\ExecutionPolicy' : 'Restricted\x00',
            'HKCU\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell\\ExecutionPolicy': 'Restricted\x00'
        }
        result = any(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'Powershell is configured in Restricted mode : {result}', reverse=True)

    @admin_required
    def reg_bitlocker(self):
        hives = {
            ('HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\UseAdvancedStartup', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\\\EnableBDEWithNoTPM'): 1,
            ('HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\UseAdvancedStartup', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\UseTPM'): 1
        }
        result = any(all(self.reg_client(key) == value for key in keys) for keys, value in hives.items())
        self.pprint(result, f'Bitlocker is enabled : {result}', reverse=True)

    @admin_required
    def reg_llmnr(self):
        hives = {
            'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast': 0,
            'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\\AllowMulticast': 0
        }
        result = any(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'LLMNR, NetBIOS or mDNS is disabled : {result}', reverse=True)

    @admin_required
    def reg_applocker(self):
        hives = {
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Appx\\EnforcementMode': 1,
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Dll\\EnforcementMode': 1,
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Exe\\EnforcementMode': 1,
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Msi\\EnforcementMode': 1,
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Script\\EnforcementMode': 1
        }
        result = any(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'AppLocker rules defined : {result}', reverse=True)

    @admin_required
    def reg_autologin(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon': 1
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'gpp_autologon is enabled : {result}')

    @admin_required
    def reg_wpad(self):
        hives = {
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\AutoDetect': 0
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'WPAD is disabled : {result}', reverse=True)

    @admin_required
    def reg_wsh(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled': 0
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'Windows Script Host is disabled : {result}', reverse=True)

    @admin_required
    def reg_fw(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\EnableFirewall': 0
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'Firewall is disabled : {result}')
    
    @admin_required
    def reg_av(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\': 0
        }
        reg_items = [self.reg_client(key, subKey=True) for key in hives][0][0].items()
        
        result = []
        for key, value in reg_items:
            if len(value) > 0:
                result.append(value[0]['(Default)'])
        self.pprint('INFO', f"AMSI installed is : {result or 'Windows Defender'}")

    @admin_required
    def reg_pwsh_event(self):
        hives = {
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging': 1,
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\EnableModuleLogging': 1
        }
        result = all(self.reg_client(key) == hives.get(key) for key in hives)
        self.pprint(result, f'Powershell events are logged : {result}', reverse=True)

class Options:
    def __init__(self):
        self.secure = False
        self.output = False
        self.is_admin = False