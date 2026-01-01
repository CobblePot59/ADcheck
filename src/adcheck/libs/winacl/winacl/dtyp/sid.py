import io
import enum
from typing import List

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
class SID:
	def __init__(self):
		self.Revision:int = None
		self.SubAuthorityCount:int = None
		self.IdentifierAuthority:int = None
		self.SubAuthority:List[int] = []

		self.is_wellknown:bool = None
		self.wellknow_name:str = None
		
		self.wildcard:bool = None #this is for well-known-sid lookups
	
	@staticmethod
	def wellknown_sid_lookup(x):
		if x in well_known_sids_sid_name_map:
			return well_known_sids_sid_name_map[x]
		return False

	@staticmethod
	def wellknown_name_lookup(x):
		if x in well_known_sids_name_sid_map:
			return well_known_sids_name_sid_map[x]
		return False


	@staticmethod	
	def from_string(sid_str, wildcard = False):
		if sid_str[:4] != 'S-1-':
			raise Exception('This is not a SID')
		sid = SID()
		sid.wildcard = wildcard
		sid.Revision = 1
		sid_str = sid_str[4:]
		t = sid_str.split('-')[0]
		if t[:2] == '0x':
			sid.IdentifierAuthority = int(t[2:],16)
		else:
			sid.IdentifierAuthority = int(t)
			
		for p in sid_str.split('-')[1:]:
			try:
				p = int(p)
			except Exception as e:
				if wildcard != True:
					raise e
			sid.SubAuthority.append(p)
		return sid
		
	@staticmethod
	def from_bytes(data):
		return SID.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		sid = SID()
		sid.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.SubAuthorityCount = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.IdentifierAuthority = int.from_bytes(buff.read(6), 'big', signed = False)
		for _ in range(sid.SubAuthorityCount):
			sid.SubAuthority.append(int.from_bytes(buff.read(4), 'little', signed = False))
		return sid
		
	def to_bytes(self):
		t = self.Revision.to_bytes(1, 'little', signed = False)
		t += len(self.SubAuthority).to_bytes(1, 'little', signed = False)
		t += self.IdentifierAuthority.to_bytes(6, 'big', signed = False)
		for i in self.SubAuthority:
			t += i.to_bytes(4, 'little', signed = False)
		return t
		
	def __str__(self):
		t = 'S-1-'
		if self.IdentifierAuthority < 2**32:
			t += str(self.IdentifierAuthority)
		else:
			t += '0x' + self.IdentifierAuthority.to_bytes(6, 'big').hex().upper().rjust(12, '0')
		for i in self.SubAuthority:
			t += '-' + str(i)
		return t

	def __eq__(self, other):
		if isinstance(other, SID):
			return str(self) == str(other)
		elif isinstance(other, str):
			return str(self) == other
		return NotImplemented

	def to_sddl(self):
		x = str(self)
		return x
		# TODO: if we figure out how to properly convert the pretty names to the correct SIDs enable this part
		#       problem is that pretty names sometimes belong to full SIDs sometimes to RIDs only and there is no way to tell if it belonged to
		#       a domain-sid or a local sid
		
		#for val in sddl_val_name_map:
		#	if isinstance(val, str) is True and val == x:
		#		return sddl_val_name_map[val]
		#	elif isinstance(val, int) is True and self.SubAuthority[-1] == val:
		#		return sddl_val_name_map[val]
		#return x

	@staticmethod
	def from_sddl(sddl, domain_sid = None):
		if len(sddl) > 2:
			return SID.from_string(sddl)
		else:
			if sddl not in sddl_name_val_map:
				raise Exception('%s was not found in the well known sid definitions!' % sddl)
			account_sid_val = sddl_name_val_map[sddl]
			if isinstance(account_sid_val, str):
				return SID.from_string(account_sid_val)
			else:
				if domain_sid is None:
					raise Exception('Missing domain_sid! Cant convert "%s" to a SID' % sddl)
				return SID.from_string(domain_sid + '-' +str(account_sid_val))

# https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
# https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids

well_known_sids_name_sid_map = {
	'NULL' : 'S-1-0-0',
	'EVERYONE' : 'S-1-1-0',
	'LOCAL' : 'S-1-2-0',
	'CONSOLE_LOGON' : 'S-1-2-1',
	'CREATOR_OWNER' : 'S-1-3-0',
	'CREATOR_GROUP' : 'S-1-3-1',
	'OWNER_SERVER' : 'S-1-3-2',
	'GROUP_SERVER' : 'S-1-3-3',
	'OWNER_RIGHTS' : 'S-1-3-4',
	'NT_AUTHORITY' : 'S-1-5',
	'DIALUP' : 'S-1-5-1',
	'NETWORK' : 'S-1-5-2',
	'BATCH' : 'S-1-5-3',
	'INTERACTIVE' : 'S-1-5-4',
	'SERVICE' : 'S-1-5-6',
	'ANONYMOUS' : 'S-1-5-7',
	'PROXY' : 'S-1-5-8',
	'ENTERPRISE_DOMAIN_CONTROLLERS' : 'S-1-5-9',
	'PRINCIPAL_SELF' : 'S-1-5-10',
	'AUTHENTICATED_USERS' : 'S-1-5-11',
	'RESTRICTED_CODE' : 'S-1-5-12',
	'TERMINAL_SERVER_USER' : 'S-1-5-13',
	'REMOTE_INTERACTIVE_LOGON' : 'S-1-5-14',
	'THIS_ORGANIZATION' : 'S-1-5-15',
	'IUSR' : 'S-1-5-17',
	'LOCAL_SYSTEM' : 'S-1-5-18',
	'LOCAL_SERVICE' : 'S-1-5-19',
	'NETWORK_SERVICE' : 'S-1-5-20',
	'COMPOUNDED_AUTHENTICATION' : 'S-1-5-21-0-0-0-496',
	'CLAIMS_VALID' : 'S-1-5-21-0-0-0-497',
	'BUILTIN_ADMINISTRATORS' : 'S-1-5-32-544',
	'BUILTIN_USERS' : 'S-1-5-32-545',
	'BUILTIN_GUESTS' : 'S-1-5-32-546',
	'POWER_USERS' : 'S-1-5-32-547',
	'ACCOUNT_OPERATORS' : 'S-1-5-32-548',
	'SERVER_OPERATORS' : 'S-1-5-32-549',
	'PRINTER_OPERATORS' : 'S-1-5-32-550',
	'BACKUP_OPERATORS' : 'S-1-5-32-551',
	'REPLICATOR' : 'S-1-5-32-552',
	'ALIAS_PREW2KCOMPACC' : 'S-1-5-32-554',
	'REMOTE_DESKTOP' : 'S-1-5-32-555',
	'NETWORK_CONFIGURATION_OPS' : 'S-1-5-32-556',
	'INCOMING_FOREST_TRUST_BUILDERS' : 'S-1-5-32-557',
	'PERFMON_USERS' : 'S-1-5-32-558',
	'PERFLOG_USERS' : 'S-1-5-32-559',
	'WINDOWS_AUTHORIZATION_ACCESS_GROUP' : 'S-1-5-32-560',
	'TERMINAL_SERVER_LICENSE_SERVERS' : 'S-1-5-32-561',
	'DISTRIBUTED_COM_USERS' : 'S-1-5-32-562',
	'IIS_IUSRS' : 'S-1-5-32-568',
	'CRYPTOGRAPHIC_OPERATORS' : 'S-1-5-32-569',
	'EVENT_LOG_READERS' : 'S-1-5-32-573',
	'CERTIFICATE_SERVICE_DCOM_ACCESS' : 'S-1-5-32-574',
	'RDS_REMOTE_ACCESS_SERVERS' : 'S-1-5-32-575',
	'RDS_ENDPOINT_SERVERS' : 'S-1-5-32-576',
	'RDS_MANAGEMENT_SERVERS' : 'S-1-5-32-577',
	'HYPER_V_ADMINS' : 'S-1-5-32-578',
	'ACCESS_CONTROL_ASSISTANCE_OPS' : 'S-1-5-32-579',
	'REMOTE_MANAGEMENT_USERS' : 'S-1-5-32-580',
	'WRITE_RESTRICTED_CODE' : 'S-1-5-33',
	'NTLM_AUTHENTICATION' : 'S-1-5-64-10',
	'SCHANNEL_AUTHENTICATION' : 'S-1-5-64-14',
	'DIGEST_AUTHENTICATION' : 'S-1-5-64-21',
	'THIS_ORGANIZATION_CERTIFICATE' : 'S-1-5-65-1',
	'NT_SERVICE' : 'S-1-5-80',
	'USER_MODE_DRIVERS' : 'S-1-5-84-0-0-0-0-0',
	'LOCAL_ACCOUNT' : 'S-1-5-113',
	'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP' : 'S-1-5-114',
	'OTHER_ORGANIZATION' : 'S-1-5-1000',
	'ALL_APP_PACKAGES' : 'S-1-15-2-1',
	'ML_UNTRUSTED' : 'S-1-16-0',
	'ML_LOW' : 'S-1-16-4096',
	'ML_MEDIUM' : 'S-1-16-8192',
	'ML_MEDIUM_PLUS' : 'S-1-16-8448',
	'ML_HIGH' : 'S-1-16-12288',
	'ML_SYSTEM' : 'S-1-16-16384',
	'ML_PROTECTED_PROCESS' : 'S-1-16-20480',
	'ML_SECURE_PROCESS' : 'S-1-16-28672',
	'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY' : 'S-1-18-1',
	'SERVICE_ASSERTED_IDENTITY' : 'S-1-18-2',
	'FRESH_PUBLIC_KEY_IDENTITY' : 'S-1-18-3',
	'KEY_TRUST_IDENTITY' : 'S-1-18-4',
	'KEY_PROPERTY_MFA' : 'S-1-18-5',
	'KEY_PROPERTY_ATTESTATION' : 'S-1-18-6',
}

well_known_sids_sid_name_map = {v: k for k, v in well_known_sids_name_sid_map.items()}

# below is the list of well-known SIDs which needs RE parsing for lookup
well_known_sids_re_name_sid_map = {
	'LOGON_ID' : 'S-1-5-5-x-y',
	'ENTERPRISE_READONLY_DOMAIN_CONTROLLERS' : 'S-1-5-21-<root domain>-498',
	'ADMINISTRATOR' : 'S-1-5-21-<machine>-500',
	'GUEST' : 'S-1-5-21-<machine>-501',
	'KRBTG' : 'S-1-5-21-<domain>-502',
	'DOMAIN_ADMINS' : 'S-1-5-21-<domain>-512',
	'DOMAIN_USERS' : 'S-1-5-21-<domain>-513',
	'DOMAIN_GUESTS' : 'S-1-5-21-<domain>-514',
	'DOMAIN_COMPUTERS' : 'S-1-5-21-<domain>-515',
	'DOMAIN_DOMAIN_CONTROLLERS' : 'S-1-5-21-<domain>-516',
	'CERT_PUBLISHERS' : 'S-1-5-21-<domain>-517',
	'SCHEMA_ADMINISTRATORS' : 'S-1-5-21-<root-domain>-518',
	'ENTERPRISE_ADMINS' : 'S-1-5-21-<root-domain>-519',
	'GROUP_POLICY_CREATOR_OWNERS' : 'S-1-5-21-<domain>-520',
	'READONLY_DOMAIN_CONTROLLERS' : 'S-1-5-21-<domain>-521',
	'CLONEABLE_CONTROLLERS' : 'S-1-5-21-<domain>-522',
	'PROTECTED_USERS' : 'S-1-5-21-<domain>-525',
	'KEY_ADMINS' : 'S-1-5-21-<domain>-526',
	'ENTERPRISE_KEY_ADMINS' : 'S-1-5-21-<domain>-527',
	'RAS_SERVERS' : 'S-1-5-21-<domain>-553',
	'ALLOWED_RODC_PASSWORD_REPLICATION_GROUP' : 'S-1-5-21-<domain>-571',
	'DENIED_RODC_PASSWORD_REPLICATION_GROUP' : 'S-1-5-21-<domain>-572',
}
	
well_known_sids_re_sid_name_map = {v: k for k, v in well_known_sids_re_name_sid_map.items()}


class DOMAIN_ALIAS_RID(enum.Enum):
	ADMINS = 0x00000220 # 	A local group used for administration of the domain.
	USERS = 0x00000221 #A local group that represents all users in the domain.
	GUESTS = 0x00000222 #A local group that represents guests of the domain.
	POWER_USERS = 0x00000223 #A local group used to represent a user or set of users who expect to treat a system as if it were their personal computer rather than as a workstation for multiple users.
	ACCOUNT_OPS = 	0x00000224 #A local group that exists only on systems running server operating systems. This local group permits control over nonadministrator accounts.
	SYSTEM_OPS = 0x00000225 #A local group that exists only on systems running server operating systems. This local group performs system administrative functions, not including security functions. It establishes network shares, controls printers, unlocks workstations, and performs other operations.
	PRINT_OPS = 0x00000226 #A local group that exists only on systems running server operating systems. This local group controls printers and print queues.
	BACKUP_OPS = 0x00000227 #A local group used for controlling assignment of file backup-and-restore privileges.
	REPLICATOR = 0x00000228 #A local group responsible for copying security databases from the primary domain controller to the backup domain controllers. These accounts are used only by the system.
	RAS_SERVERS = 0x00000229 #A local group that represents RAS and IAS servers. This group permits access to various attributes of user objects.
	PREW2KCOMPACCESS = 0x0000022A #A local group that exists only on systems running Windows 2000 Server. For more information, see Allowing Anonymous Access.
	REMOTE_DESKTOP_USERS = 0x0000022B #A local group that represents all remote desktop users.
	NETWORK_CONFIGURATION_OPS = 0x0000022C #A local group that represents the network configuration.
	INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D #A local group that represents any forest trust users.
	MONITORING_USERS = 0x0000022E #A local group that represents all users being monitored.
	LOGGING_USERS = 0x0000022F #A local group responsible for logging users.
	AUTHORIZATIONACCESS = 0x00000230 #A local group that represents all authorized access.
	TS_LICENSE_SERVERS = 0x00000231 #A local group that exists only on systems running server operating systems that allow for terminal services and remote access.
	DCOM_USERS = 0x00000232 #A local group that represents users who can use Distributed Component Object Model (DCOM).
	IUSERS = 0X00000238 #A local group that represents Internet users.
	CRYPTO_OPERATORS = 0x00000239 #A local group that represents access to cryptography operators.
	CACHEABLE_PRINCIPALS_GROUP = 0x0000023B #A local group that represents principals that can be cached.
	NON_CACHEABLE_PRINCIPALS_GROUP = 0x0000023C #A local group that represents principals that cannot be cached.
	EVENT_LOG_READERS_GROUP = 0x0000023D #A local group that represents event log readers.
	CERTSVC_DCOM_ACCESS_GROUP = 0x0000023E #The local group of users who can connect to certification authorities using Distributed Component Object Model (DCOM).
	RDS_REMOTE_ACCESS_SERVERS = 0x0000023F  #A local group that represents RDS remote access servers.
	RDS_ENDPOINT_SERVERS = 0x00000240 #A local group that represents endpoint servers.
	RDS_MANAGEMENT_SERVERS = 0x00000241 #A local group that represents management servers.
	HYPER_V_ADMINS = 0x00000242 #A local group that represents hyper-v admins
	ACCESS_CONTROL_ASSISTANCE_OPS = 0x00000243 #A local group that represents access control assistance OPS.
	REMOTE_MANAGEMENT_USERS = 0x00000244 #A local group that represents remote management users.
	DEFAULT_ACCOUNT = 0x00000245 #A local group that represents the default account.
	STORAGE_REPLICA_ADMINS = 0x00000246 #A local group that represents storage replica admins.
	DEVICE_OWNERS = 0x00000247 #A local group that represents can make settings expected for Device Owners.

class DOMAIN_GROUP_RID(enum.Enum):
	ADMINS = 0x00000200 #The domain administrators' group. This account exists only on systems running server operating systems.
	USERS = 0x00000201 #A group that contains all user accounts in a domain. All users are automatically added to this group.
	GUESTS = 0x00000202 #The guest-group account in a domain.
	COMPUTERS = 0x00000203 #The domain computers' group. All computers in the domain are members of this group.
	CONTROLLERS = 0x00000204 #The domain controllers' group. All DCs in the domain are members of this group.
	CERT_ADMINS = 0x00000205 #The certificate publishers' group. Computers running Certificate Services are members of this group.
	ENTERPRISE_READONLY_DOMAIN_CONTROLLERS = 0x000001F2 #The group of enterprise read-only domain controllers.
	SCHEMA_ADMINS = 0x00000206 #The schema administrators' group. Members of this group can modify the Active Directory schema.
	ENTERPRISE_ADMINS = 0x00000207 #The enterprise administrators' group. Members of this group have full access to all domains in the Active Directory forest. Enterprise administrators are responsible for forest-level operations such as adding or removing new domains.
	POLICY_ADMINS = 0x00000208 #The policy administrators' group.
	READONLY_CONTROLLERS = 0x00000209 #The group of read-only domain controllers.
	CLONEABLE_CONTROLLERS = 0x0000020A #The group of cloneable domain controllers.
	CDC_RESERVED = 0x0000020C #The reserved CDC group.
	PROTECTED_USERS = 0x0000020D #	The protected users group.
	KEY_ADMINS = 0x0000020E #The key admins group.
	ENTERPRISE_KEY_ADMINS = 0x0000020F

class SECURITY_MANDATORY(enum.Enum):
	UNTRUSTED_RID = 0x00000000 #Untrusted.
	LOW_RID = 0x00001000 #Low integrity.
	MEDIUM_RID = 0x00002000 #Medium integrity.
	MEDIUM_PLUS_RID = 0x00002000 + 0x100 #Medium high integrity.
	HIGH_RID = 0x00003000 #High integrity.
	SYSTEM_RID = 0x00004000 #System integrity.
	PROTECTED_PROCESS_RID = 0x00005000

DOMAIN_USER_RID_ADMIN = 0x000001F4
DOMAIN_USER_RID_GUEST = 0x000001F5

SECURITY_LOCAL_SERVICE_RID  = 0x00000013
SECURITY_SERVER_LOGON_RID = 9
SECURITY_NETWORK_SERVICE_RID = 0x00000014

# https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings
sddl_name_val_map = {
	"AN" : "S-1-5-7", #Anonymous logon. The corresponding RID is SECURITY_ANONYMOUS_LOGON_RID.
	"AO" : 	DOMAIN_ALIAS_RID.ACCOUNT_OPS.value, #Account operators. The corresponding RID is DOMAIN_ALIAS_RID_ACCOUNT_OPS.
	"AU" : 	"S-1-5-11", #Authenticated users. The corresponding RID is SECURITY_AUTHENTICATED_USER_RID.
	"BA" : 	DOMAIN_ALIAS_RID.ADMINS.value, #Built-in administrators. The corresponding RID is DOMAIN_ALIAS_RID_ADMINS.
	"BG" :  DOMAIN_ALIAS_RID.GUESTS.value, #Built-in guests. The corresponding RID is DOMAIN_ALIAS_RID_GUESTS.
	"BO" : 	DOMAIN_ALIAS_RID.BACKUP_OPS.value, #Backup operators. The corresponding RID is DOMAIN_ALIAS_RID_BACKUP_OPS.
	"BU" : 	"S-1-5-32-545", #Built-in users. The corresponding RID is DOMAIN_ALIAS_RID_USERS.
	"CA" :  DOMAIN_GROUP_RID.CERT_ADMINS.value, #Certificate publishers. The corresponding RID is DOMAIN_GROUP_RID_CERT_ADMINS.
	"CD" :  DOMAIN_ALIAS_RID.CERTSVC_DCOM_ACCESS_GROUP.value, #Users who can connect to certification authorities using Distributed Component Object Model (DCOM). The corresponding RID is DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP.
	"CG" : 	"S-1-3", #Creator group. The corresponding RID is SECURITY_CREATOR_GROUP_RID.
	"CO" :  "S-1-3-0", #Creator owner. The corresponding RID is SECURITY_CREATOR_OWNER_RID.
	"DA" : 	DOMAIN_GROUP_RID.ADMINS.value, #Domain administrators. The corresponding RID is DOMAIN_GROUP_RID_ADMINS.
	"DC" : 	DOMAIN_GROUP_RID.COMPUTERS.value, #Domain computers. The corresponding RID is DOMAIN_GROUP_RID_COMPUTERS.
	"DD" : 	DOMAIN_GROUP_RID.CONTROLLERS.value, #Domain controllers. The corresponding RID is DOMAIN_GROUP_RID_CONTROLLERS.
	"DG" : 	DOMAIN_GROUP_RID.GUESTS.value, #Domain guests. The corresponding RID is DOMAIN_GROUP_RID_GUESTS.
	"DU" : 	DOMAIN_GROUP_RID.USERS.value, #Domain users. The corresponding RID is DOMAIN_GROUP_RID_USERS.
	"EA" : 	DOMAIN_GROUP_RID.ENTERPRISE_ADMINS.value, #Enterprise administrators. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_ADMINS.
	"ED" : 	SECURITY_SERVER_LOGON_RID, #Enterprise domain controllers. The corresponding RID is SECURITY_SERVER_LOGON_RID.
	"HI" : 	SECURITY_MANDATORY.HIGH_RID.value, #High integrity level. The corresponding RID is SECURITY_MANDATORY_HIGH_RID.
	"IU" : 	"S-1-5-4", #Interactively logged-on user. This is a group identifier added to the token of a process when it was logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE. The corresponding RID is SECURITY_INTERACTIVE_RID.
	"LA" : 	DOMAIN_USER_RID_ADMIN, #Local administrator. The corresponding RID is DOMAIN_USER_RID_ADMIN.
	"LG" : 	DOMAIN_USER_RID_GUEST, #Local guest. The corresponding RID is DOMAIN_USER_RID_GUEST.
	"LS" :  SECURITY_LOCAL_SERVICE_RID, #Local service account. The corresponding RID is SECURITY_LOCAL_SERVICE_RID.
	"LW" : 	SECURITY_MANDATORY.LOW_RID.value, #Low integrity level. The corresponding RID is SECURITY_MANDATORY_LOW_RID.
	"ME" : 	SECURITY_MANDATORY.MEDIUM_RID.value, #Medium integrity level. The corresponding RID is SECURITY_MANDATORY_MEDIUM_RID.
	# TODO ERROR: NO VALUE FOUND FOR THIS! "MU" :  SDDL_PERFMON_USERS, #Performance Monitor users.
	"NO" : 	DOMAIN_ALIAS_RID.NETWORK_CONFIGURATION_OPS.value, #Network configuration operators. The corresponding RID is DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS.
	"NS" : 	SECURITY_NETWORK_SERVICE_RID, #Network service account. The corresponding RID is SECURITY_NETWORK_SERVICE_RID.
	"NU" : 	"S-1-5-2", #Network logon user. This is a group identifier added to the token of a process when it was logged on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK. The corresponding RID is SECURITY_NETWORK_RID.
	"PA" : 	DOMAIN_GROUP_RID.POLICY_ADMINS.value, #Group Policy administrators. The corresponding RID is DOMAIN_GROUP_RID_POLICY_ADMINS.
	"PO" : 	DOMAIN_ALIAS_RID.PRINT_OPS.value, #Printer operators. The corresponding RID is DOMAIN_ALIAS_RID_PRINT_OPS.
	"PS" : 	"S-1-5-10", #Principal self. The corresponding RID is SECURITY_PRINCIPAL_SELF_RID.
	"PU" : 	DOMAIN_ALIAS_RID.POWER_USERS.value, #Power users. The corresponding RID is DOMAIN_ALIAS_RID_POWER_USERS.
	"RC" : 	"S-1-5-12", #Restricted code. This is a restricted token created using the CreateRestrictedToken function. The corresponding RID is SECURITY_RESTRICTED_CODE_RID.
	"RD" : 	DOMAIN_ALIAS_RID.REMOTE_DESKTOP_USERS.value, #Terminal server users. The corresponding RID is DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS.
	"RE" : 	DOMAIN_ALIAS_RID.REPLICATOR.value, #Replicator. The corresponding RID is DOMAIN_ALIAS_RID_REPLICATOR.
	"RO" : 	DOMAIN_GROUP_RID.ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.value, #Enterprise Read-only domain controllers. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.
	"RS" :  DOMAIN_ALIAS_RID.RAS_SERVERS.value, #RAS servers group. The corresponding RID is DOMAIN_ALIAS_RID_RAS_SERVERS.
	"RU" :	DOMAIN_ALIAS_RID.PREW2KCOMPACCESS.value, #Alias to grant permissions to accounts that use applications compatible with operating systems previous to Windows 2000. The corresponding RID is DOMAIN_ALIAS_RID_PREW2KCOMPACCESS.
	"SA" : 	DOMAIN_GROUP_RID.SCHEMA_ADMINS.value, #Schema administrators. The corresponding RID is DOMAIN_GROUP_RID_SCHEMA_ADMINS.
	"SI" : 	SECURITY_MANDATORY.SYSTEM_RID.value, #System integrity level. The corresponding RID is SECURITY_MANDATORY_SYSTEM_RID.
	"SO" : 	DOMAIN_ALIAS_RID.SYSTEM_OPS.value, #Server operators. The corresponding RID is DOMAIN_ALIAS_RID_SYSTEM_OPS.
	"SU" : 	"S-1-5-6", #Service logon user. This is a group identifier added to the token of a process when it was logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE. The corresponding RID is SECURITY_SERVICE_RID.
	"SY" :	"S-1-5-18", #Local system. The corresponding RID is SECURITY_LOCAL_SYSTEM_RID.
	"WD" : 	"S-1-1-0",
}

sddl_val_name_map = {v: k for k, v in sddl_name_val_map.items()}

if __name__ == '__main__':
	sid = SID.from_string('S-1-15-2-1')
	print(sid.to_sddl())
