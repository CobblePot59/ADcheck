from adcheck.modules.connection import ADClient, AioSMBClient, SMBRegClient, WMIquery
from adcheck.modules.utils import admin_required
from adcheck.modules.constants import PRIVESC_GROUP, SUPPORTED_ENCRYPTION
from winsddl.constants import WELL_KNOWN_SIDS
from winsddl import SDDLParser
from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone
from pathlib import Path
import asyncio
import msuaccalc
import json
import re

class ADcheck:
    def __init__(self, domain, username, password, hashes, aes_key, hostname, dc_ip, url, options=None):
        self.domain = domain
        self.base_dn = f"DC={domain.split('.')[0]},DC={domain.split('.')[1]}"
        self.username = username
        self.password = password
        self.hashes = hashes
        self.nthash = self.hashes.split(":")[1] if hashes and ':' in hashes else ''
        self.aes_key = aes_key
        self.hostname = hostname
        self.dc_ip = dc_ip
        self.url = url
        self.smb_url = re.sub(r'^[^+]+', 'smb', self.url)
        self.is_secure = options.secure
        self.do_kerberos = options.kerberos
        self.output = options.output
        self.is_admin = options.is_admin
        self.debug = options.debug
        self.report_results = []
        self.console = Console()

    async def connect(self):
        self.ad_client = await self._ad_client()
        self.smb_client = await self._smb_client()
        self.reg_client = await self._reg_client()
        self.wmi_client = self._wmi_client
        await self.update_entries()

    async def disconnect(self):
        if hasattr(self, 'reg_client') and self.reg_client:
            await asyncio.wait_for(self.reg_client.disconnect(), timeout=2.0)
        if hasattr(self, 'smb_client') and self.smb_client:
            await asyncio.wait_for(self.smb_client.disconnect(), timeout=2.0)
        if hasattr(self, 'ad_client') and self.ad_client:
            await asyncio.wait_for(self.ad_client.disconnect(), timeout=2.0)

    async def _ad_client(self):
        ad_client = ADClient(domain=self.domain, url=self.url)
        await ad_client.connect()
        return ad_client

    async def _smb_client(self):
        smb_client = AioSMBClient(self.smb_url)
        await smb_client.connect()
        return smb_client

    async def _reg_client(self):
        reg_client = SMBRegClient(self.smb_client)
        await reg_client.connect()
        return reg_client

    async def _wmi_client(self, query, namespace='root/cimv2'):
        return await WMIquery(self.dc_ip, self.username, self.password, self.domain, query, namespace).run()

    async def update_entries(self):
        self.all_entries = await self.ad_client.get_ADobjects()
        self.user_entries = await self.ad_client.get_ADobjects(custom_filter='(&(objectClass=user)(!(objectClass=computer)))')
        self.computer_entries = await self.ad_client.get_ADobjects(custom_filter='(objectClass=computer)')
        self.policies_entries = [entry for entry in (await self.ad_client.get_ADobjects(custom_filter='(objectClass=groupPolicyContainer)')) if 'displayName' in entry]
        self.root_entry = next(iter(await self.ad_client.get_ADobjects(custom_filter=f"(&(objectClass=domain)(distinguishedName={self.base_dn}))")), None)
        self.domain_sid = (await self.domain_controlers(_return=True))[0].get('objectSid')[:41]
        self.NEW_WELL_KNOWN_SIDS = {key.replace('domain-', self.domain_sid): value for key, value in WELL_KNOWN_SIDS.items()}
        self.PRIVESC_GROUP = {key.replace('domain', self.domain_sid): value for key, value in PRIVESC_GROUP.items()}

    def pprint(self, result, message, reverse=False, display=True):
        import sys

        name = sys._getframe(1).f_code.co_name
        color_code = {'black': 'black', 'red': 'red', 'green': 'green'}
        ansi_color_code = {'black': '\033[30m', 'red': '\033[31m', 'green': '\033[32m', 'default': '\033[0m'}
        color = color_code.get('black') if result == 'INFO' else (color_code.get('red') if (result and not reverse) or (not result and reverse) else color_code.get('green'))
        term_color = ansi_color_code.get('black') if result == 'INFO' else (ansi_color_code.get('red') if (result and not reverse) or (not result and reverse) else ansi_color_code.get('green'))

        if display:
            if result == 'INFO':
                print(message)
            else:
                print(f"{term_color}{message}{ansi_color_code.get('default')}")

        if self.output:
            self.report_results.append({"name": name, "color": color, "message": message})

    async def domain_controlers(self, _return=False):
        result = []
        for computer in self.computer_entries:
            if 'SERVER_TRUST_ACCOUNT' in msuaccalc(computer.get('userAccountControl')):
                result.append(computer)

        result2 = [dc.get('sAMAccountName') for dc in result]
        if _return:
            return result
        else:
            self.pprint('INFO', f'Domain Controllers: {result2}')

    async def get_policies(self):
        unc_path = f'\\\\{self.dc_ip}\\sysvol\\{self.domain}\\Policies'
        await self.smb_client.download_tree(unc_path, 'GPOS')
        print(f"\n📁 \033[37mGPOs downloaded to current folder: ./GPOS\033[0m\n\n")

    async def can_add_computer(self):
        result = self.root_entry.get('ms-DS-MachineAccountQuota')
        self.pprint(result, f'Non-admin users can add up to {result} computer(s) to a domain')

    async def accounts_never_expire(self):
        password_unexpire = []
        for user in self.user_entries:
            if 'DONT_EXPIRE_PASSWORD' in msuaccalc(user.get('userAccountControl')):
                password_unexpire.append(user.get('sAMAccountName'))

        result = False
        if len(password_unexpire) > 50:
            result = True
        self.pprint(result, f'Number of accounts which have never expiring passwords : {len(password_unexpire)}')

    async def native_admin_logon(self):
        for user in self.user_entries:
            if user.get('objectSid') == f'{self.domain_sid.rstrip("-")}-500':
                admin_lastLogon = user.get('lastLogon')
        admin_lastLogon_date = datetime.strptime(str(admin_lastLogon), '%Y-%m-%d %H:%M:%S.%f%z').date()
        ndays = (datetime.now().date() - admin_lastLogon_date).days

        result = False
        if ndays < 30:
            result = True
        self.pprint(result, f'The native administrator account has been used recently : {ndays} day(s) ago')

    async def admin_can_be_delegated(self):
        result = []
        for user in self.user_entries:
            if 'adminCount' in user and user.get('cn') != 'krbtgt' and 'NOT_DELEGATED' not in msuaccalc(user.get('userAccountControl')):
                result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Admin accounts that can be delegated : {result}')

    async def admins_schema(self):
        group = (await self.ad_client.msldap_client.get_dn_for_objectsid(f'{self.domain_sid.rstrip("-")}-518'))[0]
        result = [member.sAMAccountName async for member, e in self.ad_client.msldap_client.get_group_members(group)]
        self.pprint(result, f'Accounts in Schema Admins group : {result}')

    async def admin_not_protected(self):
        result = []
        for user in self.user_entries:
            if 'adminCount' in user and 'memberOf' in user and user.get('cn') != 'krbtgt':
                is_protected_user = False
                for group in user.get('memberOf'):
                    if 'CN=Protected Users' in group:
                        is_protected_user = True
                        break
                if not is_protected_user:
                    result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Admin accounts not in Protected Users group : {result}')

    async def ldap_signing(self):
        from ldap3.core.exceptions import LDAPBindError

        try:
            url = self.url.replace(self.url.split('://')[0], 'ldap+simple')
            ad_client = ADClient(domain=self.domain, url=url)
            await ad_client.connect()
            await ad_client.disconnect()
            self.pprint(True, f'LDAP signature was required on target : False')
        except LDAPBindError as e:
            if 'strongerAuthRequired:' in str(e):
                self.pprint(False, f'LDAP signature was required on target : True')

    async def channel_binding(self):
        ad_client = ADClient(domain=self.domain, url=self.url.replace(self.url.split('+')[0], 'ldaps'))
        try:
            await ad_client.connect(cb_data=b'\x00' * 73)
            err = str(ad_client.msldap_client_conn_err)

            if 'data 80090346' in err:
                result = True
            else:
                result = False
            self.pprint(result, f'Channel binding enforced : {result}', reverse=True)
        except Exception as e:
            if 'Connect to the LDAP server before binding.' in str(e):
                self.pprint(True, f'Channel binding enforced : False')
        finally:
            await ad_client.disconnect()

    async def pre2000_group(self):
        group_entries = await self.ad_client.get_ADobjects(custom_filter='(objectClass=group)')
        members = [group.get('member') for group in group_entries if group.get('objectSid') == 'S-1-5-32-554'][0]
        result = any('S-1-5-11' in user for user in (members or []))
        self.pprint(result, f'Pre-Windows 2000 Compatible Access group members contain "Authenticated Users : {result}')

    async def privesc_group(self):
        result = {}
        groups = [dn[0] for key in self.PRIVESC_GROUP if (dn := await self.ad_client.msldap_client.get_dn_for_objectsid(key)) and dn[0]]
        for group in groups:
            if group is None:
                continue
            result[group] = [member.sAMAccountName async for member, e in self.ad_client.msldap_client.get_group_members(group)]
        
        table = Table(title="Privesc Groups")

        table.add_column("Group DN", style="cyan", no_wrap=True)
        table.add_column("Members (sAMAccountName)", style="green")

        for group_dn, members in result.items():
            if members:
                for i, member in enumerate(members):
                    if i == 0:
                        table.add_row(group_dn, member)
                    else:
                        table.add_row("", member)
            else:
                table.add_row(group_dn, "-")

        self.console.print(table)

    async def krbtgt_password_age(self):
        krbtgt_pwdLastSet = (await self.ad_client.get_ADobjects(custom_base_dn=f'CN=krbtgt,CN=Users,{self.base_dn}'))[0].get('pwdLastSet')
        krbtgt_pwdLastSet_date = datetime.strptime(str(krbtgt_pwdLastSet), '%Y-%m-%d %H:%M:%S.%f%z').date()
        ndays = (datetime.now().date() - krbtgt_pwdLastSet_date).days

        result = False
        if ndays > 40:
            result = True
        self.pprint(result, f'Kerberos password last changed : {ndays} day(s) ago')

    # async def spooler(self):
    #     from impacket.dcerpc.v5 import transport, rprn

    #     rpctransport = transport.DCERPCTransportFactory(rf'ncacn_np:{self.dc_ip}[\pipe\spoolss]')
    #     if self.do_kerberos:
    #         rpctransport = transport.DCERPCTransportFactory(rf'ncacn_np:{self.hostname}[\pipe\spoolss]')
    #         rpctransport.set_kerberos(True, kdcHost=self.hostname)
    #     rpctransport.set_credentials(domain=self.domain, username=self.username, password=self.password, nthash=self.nthash, aesKey=self.aes_key)
    #     dce = rpctransport.get_dce_rpc()

    #     try:
    #         dce.connect()
    #         dce.bind(rprn.MSRPC_UUID_RPRN)
    #         self.pprint(True, 'Spooler service is enabled on remote target : True')
    #     except Exception as e:
    #         if 'STATUS_ACCESS_DENIED' in str(e):
    #             message = 'Access denied'
    #         elif 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
    #             message = 'Spooler service is enabled on remote target: False'
    #         else:
    #             message = f'Unhandled exception occurred: {e}'
    #         self.pprint(False, message)

    async def reversible_password(self):
        result = []
        for user in self.user_entries:
            if 'ENCRYPTED_TEXT_PASSWORD_ALLOWED' in msuaccalc(user.get('userAccountControl')):
                result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Accounts which have reversible passwords : {result}')

    async def inactive_accounts(self):
        result = []
        for user in self.user_entries:
            if 'lastLogon' not in user:
                continue

            user_lastLogon = str(user.get('lastLogon'))
            if user_lastLogon == '1601-01-01 00:00:00+00:00':
                continue

            user_lastLogon_date = datetime.strptime(user_lastLogon, '%Y-%m-%d %H:%M:%S.%f%z').date()
            ndays = (datetime.now().date() - user_lastLogon_date).days
            if ndays >= 90:
                result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Number of inactive accounts: {len(result)}')

    async def locked_accounts(self):
        naccounts = []
        for user in self.user_entries:
            if 'LOCKOUT' in msuaccalc(user.get('userAccountControl')):
                naccounts.append(user.get('sAMAccountName'))
        result = False
        if len(naccounts) > 5:
            result = True
        self.pprint(result, f'Locked accounts : {naccounts}')

    async def des_authentication(self):
        result = []
        for user in self.user_entries:
            if 'USE_DES_KEY_ONLY' in msuaccalc(user.get('userAccountControl')):
                result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Accounts which can use des authentication : {result}')

    async def asreproast(self):
        result = []
        for user in self.user_entries:
            if 'DONT_REQ_PREAUTH' in msuaccalc(user.get('userAccountControl')):
                result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Accounts vulnerable to asreproasting attack : {result}')

    async def kerberoast(self):
        result = []
        for user in self.user_entries:
            if 'servicePrincipalName' in user and user.get('cn') != 'krbtgt':
                result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Accounts vulnerable to kerberoasting attack : {result}')

    async def trusted_for_delegation(self):
        users = []
        for user in self.user_entries:
            if 'TRUSTED_FOR_DELEGATION' in msuaccalc(user.get('userAccountControl')):
                users.append(user.get('sAMAccountName'))

        computers = []
        for computer in self.computer_entries:
            if 'TRUSTED_FOR_DELEGATION' in msuaccalc(computer.get('userAccountControl')) and not 'SERVER_TRUST_ACCOUNT'  in msuaccalc(computer.get('userAccountControl')):
                computers.append(computer.get('sAMAccountName'))

        result = users + computers
        self.pprint(result, f'Trust accounts for the delegation : {result}')

    async def password_not_required(self):
        guest_dn = (await self.ad_client.msldap_client.get_dn_for_objectsid(f'{self.domain_sid.rstrip("-")}-501'))[0]
        guest = (await self.ad_client.msldap_client.get_user_by_dn(guest_dn))[0].cn

        result = []
        for user in self.user_entries:
            if 'PASSWD_NOTREQD' in msuaccalc(user.get('userAccountControl')):
                if user.get('sAMAccountName') != guest:
                    result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Accounts with password not required : {result}')

    @admin_required
    async def ntds_dump(self):
        result = []
        async for secret in self.smb_client.smbmachine.dcsync():
            for line in str(secret[0]).strip().split("\n"):
                parts = line.split(":")
                protocol = parts[0].lower()
                entry = {'protocol': protocol}
                if protocol in ('ntlm', 'ntlm_history'):
                    entry.update({
                        'domain': None if parts[1] == 'None' else parts[1],
                        'username': parts[2], 'rid': parts[3], 'sid': parts[4],
                        'lm': parts[5], 'nt': parts[6], 'timestamp': parts[7] if len(parts)>7 else None
                    })
                elif protocol == 'kerberos':
                    entry.update({
                        'domain': None if parts[1] == 'None' else parts[1],
                        'username': parts[2], 'sid': parts[3], 'etype': parts[4], 'hash': parts[5]
                    })
                else:
                    entry['raw'] = parts[1:]
                result.append(entry)
        return result

    @admin_required
    async def identical_password(self):
        ntds = await self.ntds_dump()
        hash_counts = {}

        for entry in ntds:
            hash = entry.get('nt')
            if hash:
                hash_counts[hash] = hash_counts.get(hash, 0) + 1

        result = sum(1 for cpt in hash_counts.values() if cpt > 1)
        self.pprint(result, f'Number of accounts with identical password : {result}')

    @admin_required
    async def blank_password(self):
        guest_dn = (await self.ad_client.msldap_client.get_dn_for_objectsid(f'{self.domain_sid.rstrip("-")}-501'))[0]
        guest = (await self.ad_client.msldap_client.get_user_by_dn(guest_dn))[0].cn

        result = []
        ntds = await self.ntds_dump()
        for entry in ntds:
            username = entry.get('username')
            user_hash = entry.get('nt')
            
            if user_hash == '31d6cfe0d16ae931b73c59d7e0c089c0' and username != guest:
                result.append(username)
        self.pprint(result, f'Accounts with blank password : {result}')

    async def was_admin(self):
        result = []
        for user in self.user_entries:
            if 'adminCount' in user and user.get('cn') != 'krbtgt' and user.get('objectSid') != 'S-1-5-32-544':
                result.append(user.get('sAMAccountName'))
        self.pprint(result, f'Accounts that were an admin : {result}')

    async def gpo_by_ou(self):
        policies = [{'name': policy.get('name'), 'displayName': policy.get('displayName')} for policy in self.policies_entries]

        groups = []
        for entry in self.all_entries:
            if 'gPLink' in entry:
                groups.append({'dn': entry.get('distinguishedName'), 'name': re.findall(r'{(.*?)}', entry.get('gPLink'))})

        table = Table(title="Group Policy Objects by OU")

        table.add_column("OU DN", style="cyan", no_wrap=True)
        table.add_column("GPO Name", style="green")
        table.add_column("Display Name", style="magenta")
        for group in groups:
            group_dn = group.get('dn')
            gp_links = []
            for name in group.get('name'):
                for policy in policies:
                    if policy.get('name') == f'{{{name}}}':
                        gp_links.append((policy.get('name'), policy.get('displayName')))

            if gp_links:
                for i, (name, display) in enumerate(gp_links):
                    if i == 0:
                        table.add_row(group_dn, name, display)
                    else:
                        table.add_row("", name, display)
            else:
                table.add_row(group_dn, "-", "-")

        self.console.print(table)

    async def smb_signing(self):
        result = self.smb_client.smbconn.signing_required
        self.pprint(result, f'SMB signing is required : {result}', reverse=True)

    async def password_policy(self):
        from adcheck.modules.constants import PWD_PROPERTIES

        result = {
                    'lockoutDuration': str(self.root_entry.get('lockoutDuration')),
                    'lockOutObservationWindow': str(self.root_entry.get('lockOutObservationWindow')),
                    'maxPwdAge': str(self.root_entry.get('maxPwdAge')),
                    'minPwdAge': str(self.root_entry.get('minPwdAge')),
                    'minPwdLength': str(self.root_entry.get('minPwdLength')),
                    'pwdHistoryLength': str(self.root_entry.get('pwdHistoryLength')),
                    'pwdProperties': PWD_PROPERTIES.get(int(self.root_entry.get('pwdProperties')))
                }
        self.pprint('INFO', f'Default password policy :\n{json.dumps(result, indent=4)}')

    async def functional_level(self):
        from adcheck.modules.constants import FOREST_LEVELS

        result = FOREST_LEVELS.get(int(self.root_entry.get('msDS-Behavior-Version')))
        self.pprint('INFO', f'Functional level of domain is : {result}')

    async def force_logoff(self):
        result = (self.root_entry.get('forceLogoff') == 0)
        self.pprint(result, f'Force logoff when logon hours expire : {result}', reverse=True)

    async def can_update_dns(self):
        result, e = await self.ad_client.add_DNSentry(domain=self.domain, hostname='fakehost', ip='7.7.7.7')
        # await self.ad_client.del_DNSentry(domain=self.domain, hostname='fakehost')
        self.pprint(result, f'User can create dns record : {result}')

    async def auth_attributes(self):
        attributes = ['altSecurityIdentities', 'userPassword', 'unixUserPassword', 'unicodePwd', 'msDS-HostServiceAccount']
        users_attribute = {}
        for attribute in attributes:
            users_attribute[attribute] = []
            for user in self.user_entries:
                if attribute in user:
                    users_attribute[attribute].append(user.get('sAMAccountName'))
        for attribute, result in users_attribute.items():
            self.pprint(result, f'Accounts with {attribute} attributes: {result}')

    @admin_required
    async def laps(self):
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

    async def pso(self):
        pso = await self.ad_client.get_ADobjects(custom_filter='(objectClass=msDS-PasswordSettings)')

        result = []
        if pso:
            for i in range(len(pso)):
                result.append(
                    {
                        pso[i].get('name'): {
                            'lockoutDuration': abs(float(pso[i].get('msDS-LockoutDuration'))) / 600000000,
                            'lockOutObservationWindow': abs(float(pso[i].get('msDS-LockoutObservationWindow'))) / 600000000,
                            'lockoutThreshold': pso[i].get('msDS-LockoutThreshold'),
                            'maxPwdAge': abs(float(pso[i].get('msDS-MaximumPasswordAge')) / (10**7 * 60 * 60 * 24)),
                            'minPwdAge': abs(float(pso[i].get('msDS-MinimumPasswordAge')) / (10**7 * 60 * 60 * 24)),
                            'minPwdLength': pso[i].get('msDS-MinimumPasswordLength'),
                            'psoAppliesTo': pso[i].get('msDS-PSOAppliesTo'),
                            'pwdComplexity': pso[i].get('msDS-PasswordComplexityEnabled'),
                            'pwdHistoryLength': pso[i].get('msDS-PasswordHistoryLength'),
                            'pwdReversibleEncryption': pso[i].get('msDS-PasswordReversibleEncryptionEnabled'),
                            'pwdSettingsPrecedence': pso[i].get('msDS-PasswordSettingsPrecedence'),
                        }
                    }
                )
        self.pprint('INFO', f'Password Settings Object :\n{json.dumps(result, indent=4)}')

    async def supported_encryption(self):
        dcs = await self.domain_controlers(_return=True)
        encryption_values = [int(dc.get('msDS-SupportedEncryptionTypes')) for dc in dcs]
        dcs_encryption = [f"{dc.get('sAMAccountName')}: [{SUPPORTED_ENCRYPTION.get(value)}]" for dc, value in zip(dcs, encryption_values)]
        result = not all(value in {8, 16, 24} for value in encryption_values)
        self.pprint(result, f'Supported encryption by Domain Controllers : \n{json.dumps(dcs_encryption, indent=4)}')

    async def constrained_delegation(self):
        result = []
        for computer in self.computer_entries:
            if 'msDS-AllowedToDelegateTo' in computer:
                result.append(f"{computer.get('sAMAccountName')}: {computer.get('msDS-AllowedToDelegateTo')}")
        self.pprint(result, f'Computers with constrained delegation : {json.dumps(result, indent=4)}')

    async def rbac(self):
        result = []
        for computer in self.computer_entries:
            if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in computer:
                result.append(computer.get('sAMAccountName'))
        self.pprint(result, f'Computers with rbac :{result}')

    async def gMSA(self):
        gMSAs = await self.ad_client.get_ADobjects(custom_filter='(objectClass=msDS-GroupManagedServiceAccount)')

        result = []
        if gMSAs:
             for gMSA in gMSAs:
                result.append({'dn': gMSA.get('distinguishedName'), 'msDS-HostServiceAccountBL': gMSA.get('msDS-HostServiceAccountBL'), 'msDS-ManagedPasswordInterval': gMSA.get('msDS-ManagedPasswordInterval')})
        self.pprint('INFO', f'Group Managed Service Accounts : {json.dumps(result, indent=4)}')

    async def silos(self):
        authn_container = await self.ad_client.get_ADobjects(custom_base_dn=f'CN=AuthN Policy Configuration,CN=Services,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=*)')

        authn_policies = []
        for policy in authn_container:
            if 'msDS-AuthNPolicyEnforced' in policy:
                authn_policies.append(policy)

        authn_silos = []
        for policy in authn_container:
            if 'msDS-AuthNPolicySiloEnforced' in policy:
                authn_silos.append(policy)

        authn_policy_dict = {authn_policy.get('distinguishedName'): authn_policy for authn_policy in authn_policies}

        result = []
        for authn_silo in authn_silos:
            result.append(
                {
                    'name': authn_silo.get('name'),
                    'AuthNPolicySiloEnforced': authn_silo.get('msDS-AuthNPolicySiloEnforced'),
                    'AuthNPolicySiloMembers': authn_silo.get('msDS-AuthNPolicySiloMembers'),
                    'ComputerAuthNPolicy': {
                        'name': authn_policy_dict.get(authn_silo.get('msDS-ComputerAuthNPolicy'), {}).get('name'),
                        'ComputerTGTLifetime': float(authn_policy_dict.get(authn_silo.get('msDS-ComputerAuthNPolicy'), {}).get('msDS-ComputerTGTLifetime', 0)) / 600000000
                            if authn_policy_dict.get(authn_silo.get('msDS-ComputerAuthNPolicy'), {}).get('msDS-ComputerTGTLifetime') else None,
                    },
                    'ServiceAuthNPolicy': {
                        'name': authn_policy_dict.get(authn_silo.get('msDS-ServiceAuthNPolicy'), {}).get('name'),
                        'ServiceAllowedNTLMNetworkAuthentication': authn_policy_dict.get(authn_silo.get('msDS-ServiceAuthNPolicy'), {}).get('msDS-ServiceAllowedNTLMNetworkAuthentication'),
                        'ServiceTGTLifetime': float(authn_policy_dict.get(authn_silo.get('msDS-ServiceAuthNPolicy'), {}).get('msDS-ServiceTGTLifetime', 0)) / 600000000
                            if authn_policy_dict.get(authn_silo.get('msDS-ServiceAuthNPolicy'), {}).get('msDS-ServiceTGTLifetime') else None,
                    },
                    'UserAuthNPolicy': {
                        'name': authn_policy_dict.get(authn_silo.get('msDS-UserAuthNPolicy'), {}).get('name'),
                        'StrongNTLMPolicy': authn_policy_dict.get(authn_silo.get('msDS-UserAuthNPolicy'), {}).get('msDS-StrongNTLMPolicy'),
                        'UserAllowedNTLMNetworkAuthentication': authn_policy_dict.get(authn_silo.get('msDS-UserAuthNPolicy'), {}).get('msDS-UserAllowedNTLMNetworkAuthentication'),
                        'UserTGTLifetime': float(authn_policy_dict.get(authn_silo.get('msDS-UserAuthNPolicy'), {}).get('msDS-UserTGTLifetime', 0)) / 600000000
                            if authn_policy_dict.get(authn_silo.get('msDS-UserAuthNPolicy'), {}).get('msDS-UserTGTLifetime') else None,
                    }
                }

            )
        self.pprint('INFO', f'Authentication policy silos :\n{json.dumps(result, indent=4)}')

    async def recycle_bin(self):
        result = True if 'msDS-EnabledFeatureBL' in (await self.ad_client.get_ADobjects(custom_base_dn=f'CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=*)'))[0] else False
        self.pprint(result, f'Recycle Bin is enabled : {result}', reverse=True)

    @admin_required
    async def control_delegations(self):
        from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

        # schema_objects = await self.ad_client.get_ADobjects(custom_base_dn=f'CN=Schema,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=classSchema)', custom_attributes=[b'cn', b'schemaIDGUID'])
        # schema_attributes = await self.ad_client.get_ADobjects(custom_base_dn=f'CN=Schema,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=attributeSchema)', custom_attributes=[b'cn', b'schemaIDGUID'])
        # extended_rights = await self.ad_client.get_ADobjects(custom_base_dn=f'CN=Extended-Rights,CN=Configuration,{self.base_dn}', custom_filter='(objectClass=controlAccessRight)', custom_attributes=[b'cn', b'rightsGuid'])

        ous_object = (await self.ad_client.get_ADobjects(custom_filter='(objectClass=organizationalUnit)', custom_attributes=[b'distinguishedName', b'nTSecurityDescriptor']))
        containers_name = [f'CN=Computers,{self.base_dn}', f'CN=ForeignSecurityPrincipals,{self.base_dn}', f'CN=Keys,{self.base_dn}', f'CN=Managed Service Accounts,{self.base_dn}', f'CN=Program Data,{self.base_dn}', f'CN=Users,{self.base_dn}']
        containers_object = [(await self.ad_client.get_ADobjects(custom_base_dn=container,custom_filter='(objectClass=container)', custom_attributes=[b'distinguishedName', b'nTSecurityDescriptor']))[0] for container in containers_name]
        domains_object = await self.ad_client.get_ADobjects(custom_filter='(objectClass=Domain)', custom_attributes=[b'distinguishedName', b'nTSecurityDescriptor'])

        containers =  ous_object + containers_object + domains_object
        for container in containers:
            dn = container.get('distinguishedName')
            raw_sd = container.get('nTSecurityDescriptor')

            security_descriptor = SECURITY_DESCRIPTOR().from_bytes(raw_sd)
            sd_parser = SDDLParser()
            sd_parser.parse(security_descriptor.to_sddl())
            sd_parser.to_rich(console=self.console, title=dn, sensitive_trustee=True, debug=self.debug)

    # NOTE: BLOODHOUND DO THAT

    async def krbtgt_encryption(self):
        encryption_type = int((await self.ad_client.get_ADobjects(custom_base_dn=f'CN=krbtgt,CN=Users,{self.base_dn}'))[0].get('msDS-SupportedEncryptionTypes'))
        result = encryption_type not in {8, 16, 24}
        self.pprint(result, f'Supported Kerberos encryption algorithms : {SUPPORTED_ENCRYPTION.get(encryption_type)}')

    async def bitlocker(self):
        recovery_information = await self.ad_client.get_ADobjects(custom_filter='(objectClass=msFVE-RecoveryInformation)')
        result = []
        if recovery_information:
            for computer in recovery_information:
                result.append(str(computer.get('distinguishedName')).split(','))
        self.pprint('INFO', f'Computers with bitlocker keys : {result}')

    async def gpp_password(self):
        result = []
        for file_path in Path('GPOS').rglob('*.xml'):
            for line in open(file_path):
                if 'cpassword' in line:
                    entry = Path(file_path).parts[1]
                    for policy in self.policies_entries:
                        if entry == policy.get('cn'):
                            result.append(policy.get('displayName'))
        self.pprint(result, f'Group Policy containing a password : {result}')

    async def timeroast(self):
        computers_noLogonCount = [computer.get('sAMAccountName') for computer in (await self.ad_client.get_ADobjects(custom_filter='(&(userAccountControl=4128)(logonCount=0))')) or []]
        result = []
        for computer in computers_noLogonCount:
            try:
                smb_url = re.sub(r'\\([^:]+):([^@]+)@', f'\\\\{computer}:{computer.lower().replace("$", "")}@', self.smb_url)
                smb_client = AioSMBClient(smb_url)
                await smb_client.connect()
            except Exception as e:
                if 'NTStatus.NOLOGON_WORKSTATION_TRUST_ACCOUNT' in str(e):
                    result.append(computer)
        self.pprint(result, f'Accounts vulnerable to timeroasting attack : {result}')

    async def kerberos_hardened(self):
        result = {}
        for file_path in Path('GPOS').rglob('*.inf'):
            for line in open(file_path, encoding='utf-16'):
                match = re.match(r"(MaxTicketAge|MaxRenewAge|MaxServiceAge|MaxClockSkew|TicketValidateClient)\s*=\s*(\d+)", line)
                if match:
                    result[match.group(1)] = match.group(2)
        self.pprint('INFO', f'Kerberos config :\n{json.dumps(result, indent=4)}')

    @admin_required
    async def audit_policy(self):
        from csv import DictReader

        try:
            unc_path = f'\\\\{self.dc_ip}\\C$\\Windows\\System32\\GroupPolicy\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv'
            file_content = await self.smb_client.read_file(unc_path)

            csv_reader = DictReader(file_content.splitlines())
            result = [{'Subcategories': row.get('Subcategory'), 'Inclusion Settings': row.get('Inclusion Setting')} for row in csv_reader]
            self.pprint('INFO', f'Audit policy configured : \n{json.dumps(result, indent=4)}')
        except Exception as e:
            if 'OBJECT_PATH_NOT_FOUND' in str(e):
                self.pprint(True, 'Audit policy not configured')

    async def priv_rights(self):
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
        table = Table(title="Privilege Rights")

        table.add_column("Right", style="cyan", no_wrap=True)
        table.add_column("Accounts / SIDs", style="green")

        for right, accounts in result.items():
            accounts_str = ', '.join(accounts) if accounts else "-"
            table.add_row(right, accounts_str)

        self.console.print(table)

    async def policies_ace(self):
        unc_path = rf'\\{self.dc_ip}\sysvol\{self.domain}\Policies'
        tree = await self.smb_client.list_tree_with_sd(unc_path)
        
        for unc_path, security_descriptor in tree.items():
            sd_parser = SDDLParser()
            sd_parser.parse(security_descriptor.to_sddl())

            display_path = unc_path.replace(rf'\\{self.dc_ip}\sysvol\{self.domain}\Policies', 'SYSVOL\\Policies')
            title = f"\n[bold yellow]{display_path}[/bold yellow]\n"

            sd_parser.to_rich(console=self.console, title=title, sensitive_trustee=True, sensitive_rights=True, debug=self.debug)

    async def users_description(self):
        result = []
        for user in self.user_entries:
            if 'description' in user and not self.NEW_WELL_KNOWN_SIDS.get(user.get('objectSid')):
                result.append(user.get('sAMAccountName'))
        self.pprint('INFO', f'Users with description : {result}')

    # async def namedpipes(self):
    #     result = [pipe.get_longname() for pipe in self.smb_client.listPath('IPC$', r'\\*')]
    #     self.pprint('INFO', f'Named Pipes :\n{json.dumps(result, indent=4)}')

    async def ldap_anonymous(self):
        # msldap : (False, Exception('Not implemented authentication method: NONE'))
        from ldap3 import Server, Connection, ANONYMOUS, ALL

        conn = Connection(Server(f'ldap://{self.dc_ip}', get_info=ALL), authentication=ANONYMOUS)
        result = conn.bind() and conn.search(self.base_dn, '(objectClass=*)', attributes=['*']) and bool(conn.entries)
        self.pprint(result, f'Ldap anonymous bind : {result}')

    async def dfsr(self):
        msDFSR_flags = (await self.ad_client.get_ADobjects(custom_base_dn=f'CN=DFSR-GlobalSettings,CN=System,{self.base_dn}', custom_filter='(objectClass=msDFSR-GlobalSettings)'))[0].get('msDFSR-Flags')
        result = (msDFSR_flags == 48)
        self.pprint(result, f'DFSR SYSVOL is enabled : {result}', reverse=True)

    @admin_required
    async def share_ace(self):
        async for obj, otype, err in self.smb_client.smbmachine.enum_all_recursively(depth=1, fetch_share_sd=True):
            if err:
                self.console.print(f"[red]Error : {err}[/red]")
                continue

            if otype == 'share':
                security_descriptor = obj.security_descriptor.to_sddl() if obj.security_descriptor else 'No SDDL'
                sd_parser = SDDLParser()
                sd_parser.parse(security_descriptor)

                title = f"\n[bold yellow][+] Listing ACL for share:[/bold yellow] {obj.unc_path}\n"

                sd_parser.to_rich(console=self.console, title=title, sensitive_trustee=True, debug=self.debug)

    @admin_required
    async def wmi_last_update(self):
        # https://github.com/netinvent/windows_tools/blob/master/windows_tools/updates/__init__.py#L144
        hotfix_list = await self.wmi_client('SELECT Description, HotFixID, InstalledOn FROM Win32_QuickFixEngineering')
        last_update = max(hotfix_list, key=lambda x: x.get('InstalledOn')).get('InstalledOn')
        last_update_date = datetime.strptime(last_update, "%m/%d/%Y")
        ndays = (datetime.now() - last_update_date).days

        result = ndays < 30
        self.pprint(result, f'The computer is up to date (Last : {last_update}) : {result}', reverse=True)

    @admin_required
    async def wmi_last_backup(self):
        events = await self.wmi_client("SELECT * FROM Win32_NTLogEvent WHERE LogFile='Directory Service' AND EventCode=1917")
        if events:
            last_backup = max(events, key=lambda x: x.get('TimeWritten')).get('TimeWritten')
            ndays = (datetime.now(timezone.utc) - last_backup).days
            result = ndays < 1
            self.pprint(result, f'The computer was recently backed up (Last : {last_backup}) : {result}', reverse=True)
        else:
            self.pprint(True, 'The computer was never backed up')

    @admin_required
    async def reg_ca(self):
        from io import StringIO
        from csv import DictReader
        import OpenSSL.crypto
        import httpx

        key_types = {6: 'TYPE_RSA', 10: 'TYPE_DSA', 16: 'TYPE_DH', 408: 'TYPE_EC', 480: 'TYPE_SM2'}

        # Get the list of trusted CAs
        async with httpx.AsyncClient() as client:
            response = await client.get('https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV')

        trusted_ca = {row.get('SHA-256 Fingerprint'): row for row in DictReader(StringIO(response.text))}

        untrusted_ca = []
        disabled_certificates = []

        untrusted_issuers = []
        disabled_issuers = []

        # Get local certificates
        all_subkeys = {}
        ca_paths = ['AuthRoot', 'ROOT']
        for ca_path in ca_paths:
            regpath = f'HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\{ca_path}\\Certificates'
            keys = await self.reg_client.enum_keys(regpath)
            all_subkeys[ca_path] = []
            for key in keys:
                all_subkeys[ca_path].append({regpath : await self.reg_client.read_value(f'{regpath}\\{key}\\Blob')})

        # Parse local certificates
        for ca_path, subkeys in all_subkeys.items():
            for subkey in subkeys:
                for blob in subkey.values():
                    try:
                        # Start of ASN.1 sequence
                        search_range = blob[:512]
                        der_start = search_range.find(b'\x30\x82')
                        if not der_start:
                            continue

                        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, blob[der_start:])
                        issuer = ', '.join([f"{k.decode('utf-8')}:{v.decode('utf-8')}" for k, v in cert.get_issuer().get_components()])
                        digest = cert.digest("sha256").decode('utf-8').replace(':', '')
                        cert_info = {
                            'Issuer': issuer,
                            'Version': cert.get_version(),
                            'Not Before': cert.get_notBefore().decode('utf-8'),
                            'Not After': cert.get_notAfter().decode('utf-8'),
                            'Serial Number': cert.get_serial_number(),
                            'Signature Algorithm': cert.get_signature_algorithm().decode('utf-8'),
                            'Public Key': f'type: {key_types.get(cert.get_pubkey().type())}, bits: {cert.get_pubkey().bits()}',
                            'Digest': digest,
                            'Extensions': [cert.get_extension(i).get_short_name().decode('utf-8') for i in range(cert.get_extension_count())]
                        }
                    except OpenSSL.crypto.Error:
                        continue

                    # Check CA status
                    if digest not in trusted_ca:
                        untrusted_ca.append({ca_path: cert_info})
                        untrusted_issuers.append(issuer)
                    elif trusted_ca[digest].get('Microsoft Status') == 'Disabled':
                        disabled_certificates.append({ca_path: cert_info})
                        disabled_issuers.append(issuer)

        self.pprint(untrusted_issuers, f'Untrusted Certificates Issuers:\n{json.dumps(untrusted_issuers, indent=4)}')
        self.pprint(disabled_issuers, f'Disabled Certificates Issuers:\n{json.dumps(disabled_issuers, indent=4)}')

        # self.pprint(untrusted_ca, f'Untrusted Certificates:\n{json.dumps(untrusted_ca, indent=4)}')
        # self.pprint(disabled_certificates, f'Disabled Certificates:\n{json.dumps(disabled_certificates, indent=4)}')

    @admin_required
    async def reg_ace(self):
        reg_keys = ['HKLM\\SYSTEM', 'HKLM\\SECURITY', 'HKLM\\SAM']

        for reg_key in reg_keys:
            security_descriptor = await self.reg_client.security_descriptor(reg_key, as_sddl=True)
            sd_parser = SDDLParser()
            sd_parser.parse(security_descriptor)

            title = f"\n[bold yellow]{reg_key}[/bold yellow]\n"

            sd_parser.to_rich(console=self.console, title=title)

    @admin_required
    async def reg_uac(self):
        hives = {
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA': 1,
            # 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy': 0
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'UAC configuration is secure : {result}', reverse=True)

    @admin_required
    async def reg_LMHASH(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash': 1
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'LM hash storage disabled : {result}', reverse=True)
    
    @admin_required
    async def reg_NTLMv2(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel': 5
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'Authentication limited to NTLMv2 mechanism only : {result}', reverse=True)
    
    @admin_required  
    async def reg_AlwaysInstallElevated(self):
        hives = {
            'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated': 1
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'MSI packages are always installed with elevated privileges : {result}')
    
    @admin_required  
    async def reg_ipv4_only(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisabledComponents': 128
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'IPv4 preferred over IPv6 : {result}', reverse=True)

    @admin_required
    async def reg_wdigest(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential': 1
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'WDigest authentication enabled : {result}')

    @admin_required
    async def reg_lsa_cache(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount': 2
        }
        try:
            result = all([int((await self.reg_client.read_value(key)).replace('\x00', '')) >= hives.get(key) for key in hives])
            self.pprint(result, f'Too many logons are kept in the LSA cache : {result}')
        except AttributeError :
            self.pprint(True, 'LSA cache length is not defined')

    @admin_required
    async def reg_wsus_config(self):
        hives = {
            'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer': 'https://'
        }
        try:
            result = all([(await self.reg_client.read_value(key)).startswith(hives.get(key)) for key in hives])
            self.pprint(result, f'WSUS configuration is secure : {result}', reverse=True)
        except AttributeError :
            self.pprint(True, 'WSUS server is not used')

    @admin_required
    async def reg_rdp_timeout(self):
        hives = {
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\MaxDisconnectionTime': 0,
            'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\MaxDisconnectionTime': 0
        }
        try:
            result = any([await self.reg_client.read_value(key) <= hives.get(key) for key in hives])
            self.pprint(result, f'RDP session timeout is too short : {result}')
        except:
            self.pprint(True, 'RDP session timeout is not defined')

    @admin_required  
    async def reg_CredentialGuard(self):
        hives = [
            {'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity': 1},
            {'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags': 1}
        ]
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'CredentialGuard is enabled : {result}', reverse=True)

    @admin_required  
    async def reg_lsass_ppl(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL': '1'
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'Lsass runs as a protected process : {result}', reverse=True)

    @admin_required  
    async def reg_pwsh2(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine\\PSCompatibleVersion': '2.0'
        }
        result = all([hives.get(key) in (await self.reg_client.read_value(key)) for key in hives])
        self.pprint(result, f'Powershell v2 is enabled : {result}')
  
    @admin_required  
    async def reg_rdp_nla(self):
        hives = {
            'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication': 1
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'RDP use NLA : {result}', reverse=True)

    @admin_required  
    async def reg_rdp_nopth(self):
        hives = [
            {'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\DisableRestrictedAdmin': 0},
            {'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictedAdminMode': 1},
            {'HKLM\\Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation': 1}
        ]
        result = await self.reg_client.check_values(hives, any_match=True)
        self.pprint(result, f'RDP is secured over pass the hash attack : {result}', reverse=True)

    @admin_required  
    async def reg_pwsh_restricted(self):
        hives = [
            {'HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell\\ExecutionPolicy' : 'Restricted\x00'},
            {'HKCU\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell\\ExecutionPolicy': 'Restricted\x00'}
        ]
        result = await self.reg_client.check_values(hives, any_match=True)
        self.pprint(result, f'Powershell is configured in Restricted mode : {result}', reverse=True)

    @admin_required  
    async def reg_bitlocker(self):
        hives = {
            ('HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\UseAdvancedStartup', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\\\EnableBDEWithNoTPM'): 1,
            ('HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\UseAdvancedStartup', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\UseTPM'): 1
        }
        result = any([all([await self.reg_client.read_value(key) == value for key in keys]) for keys, value in hives.items()])
        self.pprint(result, f'Bitlocker is enabled : {result}', reverse=True)

    @admin_required  
    async def reg_llmnr(self):
        hives = [
            {'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast': 0},
            {'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\\AllowMulticast': 0}
        ]
        result = await self.reg_client.check_values(hives, any_match=True)
        self.pprint(result, f'LLMNR, NetBIOS or mDNS is disabled : {result}', reverse=True)

    @admin_required  
    async def reg_applocker(self):
        hives = [
            {'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Appx\\EnforcementMode': 1},
            {'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Dll\\EnforcementMode': 1},
            {'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Exe\\EnforcementMode': 1},
            {'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Msi\\EnforcementMode': 1},
            {'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\Script\\EnforcementMode': 1}
        ]
        result = await self.reg_client.check_values(hives, any_match=True)
        self.pprint(result, f'AppLocker rules defined : {result}', reverse=True)

    @admin_required  
    async def reg_autologin(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon': 1
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'gpp_autologon is enabled : {result}')

    @admin_required  
    async def reg_wpad(self):
        hives = {
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\AutoDetect': 0
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'WPAD is disabled : {result}', reverse=True)

    @admin_required
    async def reg_wsh(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled': 0
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'Windows Script Host is disabled : {result}', reverse=True)

    @admin_required
    async def reg_fw(self):
        hives = {
            'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\EnableFirewall': 0
        }
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'Firewall is disabled : {result}')

    @admin_required    
    async def reg_av(self):
        hives = {
            'HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers': 0
        }
        result = [await self.reg_client.enum_values(key) for key in hives][0]
        if result:
            result = result[0][2]
        self.pprint('INFO', f"AMSI installed is : {result or 'Windows Defender'}")

    @admin_required
    async def reg_pwsh_event(self):
        hives = [
            {'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging': 1},
            {'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\EnableModuleLogging': 1}
        ]
        result = await self.reg_client.check_values(hives)
        self.pprint(result, f'Powershell events are logged : {result}', reverse=True)

    @admin_required
    async def reg_winrm(self):
        result = {
            'Client':{
                'AllowUnencrypted': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\allow_unencrypted', default_value=0),
                'Auth': {
                    'Basic': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\auth_basic', default_value=1),
                    'Digest': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\auth_digest', default_value=1),
                    'Kerberos': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\auth_kerberos', default_value=1),
                    'Negotiate': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\auth_negotiate', default_value=1),
                    'Certificate': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\auth_certificate', default_value=1),
                    'CredSSP': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\auth_credssp', default_value=0),
                },
                'TrustedHosts': (await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Client\\trusted_hosts', default_value=' ')).replace('\x00', '')
            },
            'Service':{
                'AllowUnencrypted': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\allow_unencrypted', default_value=0),
                'Auth': {
                    'Basic': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\auth_basic', default_value=0),
                    'Kerberos': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\auth_kerberos', default_value=1),
                    'Negotiate': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\auth_negotiate', default_value=1),
                    'Certificate': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\auth_certificate', default_value=0),
                    'CredSSP': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\auth_credssp', default_value=0),
                    'CbtHardeningLevel': (await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\cbt_hardening_level', default_value='Relaxed')).replace('\x00', '')
                },
                'IPv4Filter': (await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\IPv4Filter', default_value='*')).replace('\x00', ''),
                'IPv6Filter': (await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\IPv6Filter', default_value='*')).replace('\x00', ''),
                'EnableCompatibilityHttpListener': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\http_compat_listener', default_value=0),
                'EnableCompatibilityHttpsListener': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\https_compat_listener', default_value=0),
                'AllowRemoteAccess': await self.reg_client.read_value('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service\\allow_remote_requests', default_value=1)
            }
        }
        self.pprint('INFO', f"WSManConfig :\n{json.dumps(result, indent=4)}")

class Options:
    def __init__(self):
        self.is_secure = False
        self.do_kerberos = False
        self.output = False
        self.is_admin = False
        self.debug = False