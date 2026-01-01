# TODO 
# implement https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/21f2b5f0-7376-45bb-bc31-eaa60841dbe9
# implement https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9020a075-c1af-4b03-930b-ba785743bcab

import io
import enum
from typing import List, Dict
from winacl.dtyp.sid import SID, sddl_name_val_map
from winacl.dtyp.guid import GUID
from winacl.functions.constants import SE_OBJECT_TYPE


class ACCESS_MASK(enum.IntFlag):
	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000
	MAXIMUM_ALLOWED = 0x02000000
	ACCESS_SYSTEM_SECURITY = 0x01000000
	
class STANDARD_ACCESS_MASK(enum.IntFlag):
	SYNCHRONIZE = 0x00100000
	WRITE_OWNER = 0x00080000
	WRITE_DACL = 0x00040000
	READ_CONTROL = 0x00020000
	DELETE = 0x00010000
	ALL = 0x00100000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000
	EXECUTE = 0x00020000
	READ = 0x00020000
	WRITE = 0x00020000
	REQUIRED = 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000

# https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-6.0
class ADS_ACCESS_MASK(enum.IntFlag):
	CREATE_CHILD    = 0x00000001 # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
	DELETE_CHILD    = 0x00000002 # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.
	ACTRL_DS_LIST   = 0x00000004 # Enumerate a DS object.
	SELF            = 0x00000008 # The ObjectType GUID identifies a validated write.
	READ_PROP       = 0x00000010 # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
	WRITE_PROP      = 0x00000020 # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.
	DELETE_TREE     = 0x00000040 # The right to delete all children of this object, regardless of the permissions of the children.
	LIST_OBJECT     = 0x00000080 # The right to list a particular object. For more information about this right, see the see the Controlling Object Visibility article.
	CONTROL_ACCESS  = 0x00000100 # The ObjectType GUID identifies an extended access right.
	DELETE          = 0x00010000 # The right to delete the object.
	READ_CONTROL    = 0x00020000 # The right to read data from the security descriptor of the object, not including the data in the SACL.
	GENERIC_EXECUTE = 0x00020004 # The right to read permissions on, and list the contents of, a container object.
	GENERIC_WRITE   = 0x00020028 # The right to read permissions on this object, write all the properties on this object, and perform all validated writes to this object.
	GENERIC_READ    = 0x00020094 # The right to read permissions on this object, read all the properties on this object, list this object name when the parent container is listed, and list the contents of this object if it is a container.
	WRITE_DACL      = 0x00040000 # The right to modify the DACL in the object security descriptor.
	WRITE_OWNER     = 0x00080000 # The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the ownership to other users.
	GENERIC_ALL     = 0x000f01ff # The right to create or delete children, delete a subtree, read and write properties, examine children and the object itself, add and remove the object from the directory, and read or write with an extended right.
	SYNCHRONIZE     = 0x00100000 # The right to use the object for synchronization. This right enables a thread to wait until that object is in the signaled state.
	ACCESS_SYSTEM_SECURITY = 0x01000000 # The right to get or set the SACL in the object security descriptor.
	MAXIMUM_ALLOWED = 0x02000000

class FILE_ACCESS_MASK(enum.IntFlag):
	#includes directory access as well
	FILE_READ_DATA = 1 #For a file object, the right to read the corresponding file data. For a directory object, the right to read the corresponding directory data.
	FILE_LIST_DIRECTORY = 1 #	For a directory, the right to list the contents of the directory.
	#FILE_ADD_FILE = 2 #For a directory, the right to create a file in the directory.
	FILE_WRITE_DATA = 2#For a file object, the right to write data to the file. For a directory object, the right to create a file in the directory (FILE_ADD_FILE).
	#FILE_ADD_SUBDIRECTORY = 4 #For a directory, the right to create a subdirectory.
	FILE_APPEND_DATA = 4 #	For a file object, the right to append data to the file. (For local files, write operations will not overwrite existing data if this flag is specified without FILE_WRITE_DATA.) For a directory object, the right to create a subdirectory (FILE_ADD_SUBDIRECTORY).
	#FILE_CREATE_PIPE_INSTANCE = 4 #	For a named pipe, the right to create a pipe.
	FILE_READ_EA = 8 #The right to read extended file attributes.
	FILE_WRITE_EA = 16  #The right to write extended file attributes.
	FILE_EXECUTE = 32  #	For a native code file, the right to execute the file. This access right given to scripts may cause the script to be executable, depending on the script interpreter.
	#FILE_TRAVERSE = 32  #For a directory, the right to traverse the directory. By default, users are assigned the BYPASS_TRAVERSE_CHECKING privilege, which ignores the FILE_TRAVERSE access right. See the remarks in File Security and Access Rights for more information.
	FILE_DELETE_CHILD = 64  #For a directory, the right to delete a directory and all the files it contains, including read-only files.
	FILE_READ_ATTRIBUTES = 128 #The right to read file attributes.
	FILE_WRITE_ATTRIBUTES = 256  #The right to write file attributes.
	FILE_ALL_ACCESS = 0x1f01ff #All possible access rights for a file.
	#STANDARD_RIGHTS_READ #Includes READ_CONTROL, which is the right to read the information in the file or directory object's security descriptor. This does not include the information in the SACL.
	#STANDARD_RIGHTS_WRITE #Same as STANDARD_RIGHTS_READ.
	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000
	MAXIMUM_ALLOWED = 0x02000000
	ACCESS_SYSTEM_SECURITY = 0x01000000
	SYNCHRONIZE = 0x00100000
	WRITE_OWNER = 0x00080000
	WRITE_DACL = 0x00040000
	READ_CONTROL = 0x00020000
	DELETE = 0x00010000
	ALL = 0x00100000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000
	EXECUTE = 0x00020000
	READ = 0x00020000
	WRITE = 0x00020000
	REQUIRED = 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000
	
#FILE_RIGHTS = ACCESS_MASK + STANDARD_ACCESS_MASK + FILE_ACCESS_MASK

# https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?redirectedfrom=MSDN
class SC_MANAGER_ACCESS_MASK(enum.IntFlag):
	ALL_ACCESS = 0xF003F #Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
	CREATE_SERVICE = 0x0002 #Required to call the CreateService function to create a service object and add it to the database.
	CONNECT = 0x0001  #Required to connect to the service control manager.
	ENUMERATE_SERVICE = 0x0004 #Required to call the EnumServicesStatus or EnumServicesStatusEx function to list the services that are in the database. Required to call the NotifyServiceStatusChange function to receive notification when any service is created or deleted.
	LOCK = 0x0008 #Required to call the LockServiceDatabase function to acquire a lock on the database.
	MODIFY_BOOT_CONFIG = 0x0020 #Required to call the NotifyBootConfigStatus function.
	QUERY_LOCK_STATUS = 0x0010 #	Required to call the QueryServiceLockStatus function to retrieve the lock status information for the database.

	GENERIC_READ = 0x80000000
	GENERIC_WRITE = 0x4000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL = 0x10000000

# https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights?redirectedfrom=MSDN
class SERVICE_ACCESS_MASK(enum.IntFlag):
	SERVICE_ALL_ACCESS = 0xF01FF # Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights in this table.
	SERVICE_CHANGE_CONFIG = 0x0002 # Required to call the ChangeServiceConfig or ChangeServiceConfig2 function to change the service configuration. Because this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators.
	SERVICE_ENUMERATE_DEPENDENTS = 0x0008 # Required to call the EnumDependentServices function to enumerate all the services dependent on the service.
	SERVICE_INTERROGATE = 0x0080 # Required to call the ControlService function to ask the service to report its status immediately.
	SERVICE_PAUSE_CONTINUE = 0x0040 # Required to call the ControlService function to pause or continue the service.
	SERVICE_QUERY_CONFIG = 0x0001 # Required to call the QueryServiceConfig and QueryServiceConfig2 functions to query the service configuration.
	SERVICE_QUERY_STATUS = 0x0004 # Required to call the QueryServiceStatus or QueryServiceStatusEx function to ask the service control manager about the status of the service.
	#Required to call the NotifyServiceStatusChange function to receive notification when a service changes status.
	SERVICE_START = 0x0010 # Required to call the StartService function to start the service.
	SERVICE_STOP = 0x0020 # Required to call the ControlService function to stop the service.
	SERVICE_USER_DEFINED_CONTROL = 0x0100 # Required to call the ControlService function to specify a user-defined control code.

	# TODO : value for ?ACCESS_SYSTEM_SECURITY? 	Required to call the QueryServiceObjectSecurity or SetServiceObjectSecurity function to access the SACL. The proper way to obtain this access is to enable the SE_SECURITY_NAMEprivilege in the caller's current access token, open the handle for ACCESS_SYSTEM_SECURITY access, and then disable the privilege.
	DELETE = 0x10000 #Required to call the DeleteService function to delete the service.
	READ_CONTROL = 0x20000 #Required to call the QueryServiceObjectSecurity function to query the security descriptor of the service object.
	WRITE_DAC = 0x40000 #Required to call the SetServiceObjectSecurity function to modify the Dacl member of the service object's security descriptor.
	WRITE_OWNER = 0x80000 #Required to call the SetServiceObjectSecurity function to modify the Owner and Group members of the service object's security descriptor.

# https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights?redirectedfrom=MSDN
class REGISTRY_ACCESS_MASK(enum.IntFlag):
	KEY_ALL_ACCESS = 0xF003F # Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
	KEY_CREATE_LINK = 0x0020 # Reserved for system use.
	KEY_CREATE_SUB_KEY = 0x0004 # Required to create a subkey of a registry key.
	KEY_ENUMERATE_SUB_KEYS = 0x0008 # Required to enumerate the subkeys of a registry key.
	KEY_EXECUTE = 0x20019 # Equivalent to KEY_READ.
	KEY_NOTIFY = 0x0010 # Required to request change notifications for a registry key or for subkeys of a registry key.
	KEY_QUERY_VALUE = 0x0001 # Required to query the values of a registry key.
	KEY_READ = 0x20019 # Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
	KEY_SET_VALUE = 0x0002 # Required to create, delete, or set a registry value.
	KEY_WOW64_32KEY = 0x0200 # Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
	KEY_WOW64_64KEY = 0x0100 # Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows. For more information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access registry values. Windows 2000: This flag is not supported.
	KEY_WRITE = 0x20006 # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.


#http://www.kouti.com/tables/baseattributes.htm

ExtendedRightsGUID = { 
	'ee914b82-0a98-11d1-adbb-00c04fd8d5cd' : 'Abandon Replication',
	'440820ad-65b4-11d1-a3da-0000f875ae0d' : 'Add GUID',
	'1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd' : 'Allocate Rids',
	'68b1d179-0d15-4d4f-ab71-46152e79a7bc' : 'Allowed to Authenticate',
	'edacfd8f-ffb3-11d1-b41d-00a0c968f939' : 'Apply Group Policy',
	'0e10c968-78fb-11d2-90d4-00c04f79dc55' : 'Certificate-Enrollment',
	'014bf69c-7b3b-11d1-85f6-08002be74fab' : 'Change Domain Master',
	'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' : 'Change Infrastructure Master',
	'bae50096-4752-11d1-9052-00c04fc2d4cf' : 'Change PDC',
	'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' : 'Change Rid Master',
	'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' : 'Change-Schema-Master',
	'e2a36dc9-ae17-47c3-b58b-be34c55ba633' : 'Create Inbound Forest Trust',
	'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' : 'Do Garbage Collection',
	'ab721a52-1e2f-11d0-9819-00aa0040529b' : 'Domain-Administer-Server',
	'69ae6200-7f46-11d2-b9ad-00c04f79f805' : 'Check Stale Phantoms',
	'3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' : 'Allow a DC to create a clone of itself',
	'2f16c4a5-b98e-432c-952a-cb388ba33f2e' : 'Execute Forest Update Script',
	'9923a32a-3607-11d2-b9be-0000f87a36b2' : 'Add/Remove Replica In Domain',
	'4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' : 'Query Self Quota',
	'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' : 'Replicating Directory Changes',
	'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' : 'Replicating Directory Changes All',
	'89e95b76-444d-4c62-991a-0facbeda640c' : 'Replicating Directory Changes In Filtered Set',
	'1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' : 'Manage Replication Topology',
	'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96' : 'Monitor Active Directory Replication',
	'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' : 'Replication Synchronization',
	'05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' : 'Enable Per User Reversibly Encrypted Password',
	'b7b1b3de-ab09-4242-9e30-9980e5d322f7' : 'Generate Resultant Set of Policy (Logging)',
	'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' : 'Generate Resultant Set of Policy (Planning)',
	'7c0e2a7c-a419-48e4-a995-10180aad54dd' : 'Manage Optional Features for Active Directory',
	'ba33815a-4f93-4c76-87f3-57574bff8109' : 'Migrate SID History',
	'b4e60130-df3f-11d1-9c86-006008764d0e' : 'Open Connector Queue',
	'06bd3201-df3e-11d1-9c86-006008764d0e' : 'Allows peeking at messages in the queue.',
	'4b6e08c3-df3c-11d1-9c86-006008764d0e' : 'msmq-Peek-computer-Journal',
	'4b6e08c1-df3c-11d1-9c86-006008764d0e' : 'Peek Dead Letter',
	'06bd3200-df3e-11d1-9c86-006008764d0e' : 'Receive Message',
	'4b6e08c2-df3c-11d1-9c86-006008764d0e' : 'Receive Computer Journal',
	'4b6e08c0-df3c-11d1-9c86-006008764d0e' : 'Receive Dead Letter',
	'06bd3203-df3e-11d1-9c86-006008764d0e' : 'Receive Journal',
	'06bd3202-df3e-11d1-9c86-006008764d0e' : 'Send Message',
	'a1990816-4298-11d1-ade2-00c04fd8d5cd' : 'Open Address List',
	'1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' : 'Read Only Replication Secret Synchronization',
	'45ec5156-db7e-47bb-b53f-dbeb2d03c40f' : 'Reanimate Tombstones',
	'0bc1554e-0a99-11d1-adbb-00c04fd8d5cd' : 'Recalculate Hierarchy',
	'62dd28a8-7f46-11d2-b9ad-00c04f79f805' : 'Recalculate Security Inheritance',
	'ab721a56-1e2f-11d0-9819-00aa0040529b' : 'Receive As',
	'9432c620-033c-4db7-8b58-14ef6d0bf477' : 'Refresh Group Cache for Logons',
	'1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8' : 'Reload SSL/TLS Certificate',
	'7726b9d5-a4b4-4288-a6b2-dce952e80a7f' : 'Run Protect Admin Groups Task',
	'91d67418-0135-4acc-8d79-c08e857cfbec' : 'Enumerate Entire SAM Domain',
	'ab721a54-1e2f-11d0-9819-00aa0040529b' : 'Send As',
	'ab721a55-1e2f-11d0-9819-00aa0040529b' : 'Send To',
	'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' : 'Unexpire Password',
	'280f369c-67c7-438e-ae98-1d46f3c6f541' : 'Update Password Not Required Bit',
	'be2bb760-7f46-11d2-b9ad-00c04f79f805' : 'Update Schema Cache',
	'ab721a53-1e2f-11d0-9819-00aa0040529b' : 'Change Password',
	'00299570-246d-11d0-a768-00aa006e0529' : 'Reset Password',
}

PropertySets = {
	'72e39547-7b18-11d1-adef-00c04fd8d5cd' : 'DNS Host Name Attributes',
	'b8119fd0-04f6-4762-ab7a-4986c76b3f9a' : 'Other Domain Parameters (for use by SAM)',
	'c7407360-20bf-11d0-a768-00aa006e0529' : 'Domain Password & Lockout Policies',
	'e45795b2-9455-11d1-aebd-0000f80367c1' : 'Phone and Mail Options',
	'59ba2f42-79a2-11d0-9020-00c04fc2d3cf' : 'General Information',
	'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' : 'Group Membership',
	'ffa6f046-ca4b-4feb-b40d-04dfee722543' : 'MS-TS-GatewayAccess',
	'77b5b886-944a-11d1-aebd-0000f80367c1' : 'Personal Information',
	'91e647de-d96f-4b70-9557-d63ff4f3ccd8' : 'Private Information',
	'e48d0154-bcf8-11d1-8702-00c04fb96050' : 'Public Information',
	'037088f8-0ae1-11d2-b422-00a0c968f939' : 'Remote Access Information',
	'5805bc62-bdc9-4428-a5e2-856a0f4c185e' : 'Terminal Server License Server',
	'4c164200-20c0-11d0-a768-00aa006e0529' : 'Account Restrictions',
	'5f202010-79a5-11d0-9020-00c04fc2d4cf' : 'Logon Information',
	'e45795b3-9455-11d1-aebd-0000f80367c1' : 'Web Information',
}

ValidatedWrites = {
	'bf9679c0-0de6-11d0-a285-00aa003049e2' : 'Add/Remove self as member',
	'72e39547-7b18-11d1-adef-00c04fd8d5cd' : 'Validated write to DNS host name',
	'80863791-dbe9-4eb8-837e-7f0ab55d9ac7' : 'Validated write to MS DS Additional DNS Host Name',
	'd31a8757-2447-4545-8081-3bb610cacbf2' : 'Validated write to MS DS behavior version',
	'f3a64788-5306-11d1-a9c5-0000f80367c1' : 'Validated write to service principal name',
}

#https://github.com/potatoes-and-molasses/misc_old/blob/master/sddling.py
MoreGUID = {
	'4332aad9-95ab-4e8e-a264-4965c3e1f964': 'ms-Exch-Store-Bypass-Access-Auditing',
	'91e647de-d96f-4b70-9557-d63ff4f3ccd8': 'Private-Information',
	'1131f6ae-9c07-11d1-f79f-00c04fc2dcd2': 'Read-Only-Replication-Secret-Synchronization',
	'1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8': 'Reload-SSL-Certificate',
	'89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
	'5805bc62-bdc9-4428-a5e2-856a0f4c185e': 'Terminal-Server-License-Server',
	'811d004b-e2ed-4024-8953-0f0fb0612e47': 'ms-Exch-SMTP-Accept-XShadow',
	'5bc2acab-ad7d-4878-b6cd-3122a47c6a1c': 'ms-Exch-SMTP-Send-XShadow',
	'd819615a-3b9b-4738-b47e-f1bd8ee3aea4': 'RTCPropertySet',
	'e2d6986b-2c7f-4cda-9851-d5b5f3fb6706': 'RTCUserSearchPropertySet',
	'3e0f7e18-2c7a-4c10-ba82-4d926db99a3e': 'DS-Clone-Domain-Controller',
	'd31a8757-2447-4545-8081-3bb610cacbf2': 'Validated-MS-DS-Behavior-Version',
	'80863791-dbe9-4eb8-837e-7f0ab55d9ac7': 'Validated-MS-DS-Additional-DNS-Host-Name',
	'a05b8cc2-17bc-4802-a710-e7c15ab866a2': 'Certificate-AutoEnrollment',
	'77b5b886-944a-11d1-aebd-0000f80367c1': 'Personal-Information',
	'4c164200-20c0-11d0-a768-00aa006e0529': 'User-Account-Restrictions',
	'72e39547-7b18-11d1-adef-00c04fd8d5cd': 'DNS-Host-Name-Attributes',
	'72e39547-7b18-11d1-adef-00c04fd8d5cd': 'Validated-DNS-Host-Name',
	'1f298a89-de98-47b8-b5cd-572ad53d267e': 'Exchange-Information',
	'b1b3a417-ec55-4191-b327-b72e33e38af2': 'Exchange-Personal-Information',
	'a7a9ea66-e08c-4e23-8fe7-68c40e49c6c0': 'ms-Exch-Accept-Headers-Forest',
	'9b51a1ef-79b7-4ae5-9ac8-d14c47daca46': 'RTCUserProvisioningPropertySet',
	'c307dccd-6676-4d19-95c8-d1567fab9820': 'ms-Exch-Accept-Headers-Organization',
	'04031f4f-7c36-43ea-9b49-4bd0f5f1e6af': 'ms-Exch-Accept-Headers-Routing',
	'ce4c81a8-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Add-PF-To-Admin-Group',
	'8e48d5a8-b09e-11d2-aa06-00c04f8eedd8': 'ms-Exch-Admin-Role-Administrator',
	'8e6571e0-b09e-11d2-aa06-00c04f8eedd8': 'ms-Exch-Admin-Role-Full-Administrator',
	'8ff1383c-b09e-11d2-aa06-00c04f8eedd8': 'ms-Exch-Admin-Role-Read-Only-Administrator',
	'90280e52-b09e-11d2-aa06-00c04f8eedd8': 'ms-Exch-Admin-Role-Service',
	'd19299b4-86c2-4c9a-8fa7-acb70c63023a': 'ms-Exch-Bypass-Anti-Spam',
	'ab721a52-1e2f-11d0-9819-00aa0040529b': 'Domain-Administer-Server',
	'6760cfc5-70f4-4ae8-bc39-9522d86ac69b': 'ms-Exch-Bypass-Message-Size-Limit',
	'ab721a55-1e2f-11d0-9819-00aa0040529b': 'Send-To',
	'cf0b3dc8-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Create-Public-Folder',
	'c7407360-20bf-11d0-a768-00aa006e0529': 'Domain-Password',
	'cf4b9d46-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Create-Top-Level-Public-Folder',
	'59ba2f42-79a2-11d0-9020-00c04fc2d3cf': 'General-Information',
	'bd919c7c-2d79-4950-bc9c-e16fd99285e8': 'ms-Exch-Download-OAB',
	'5f202010-79a5-11d0-9020-00c04fc2d4cf': 'User-Logon',
	'8db0795c-df3a-4aca-a97d-100162998dfa': 'ms-Exch-EPI-Impersonation',
	'bc0ac240-79a9-11d0-9020-00c04fc2d4cf': 'Membership',
	'bc39105d-9baa-477c-a34a-997cc25e3d60': 'ms-Exch-EPI-May-Impersonate',
	'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open-Address-Book',
	'06386f89-befb-4e48-baa1-559fd9221f78': 'ms-Exch-EPI-Token-Serialization',
	'e45795b2-9455-11d1-aebd-0000f80367c1': 'Email-Information',
	'cf899a6a-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Mail-Enabled-Public-Folder',
	'e45795b3-9455-11d1-aebd-0000f80367c1': 'Web-Information',
	'd74a8769-22b9-11d3-aa62-00c04f8eedd8': 'ms-Exch-Modify-PF-ACL',
	'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
	'd74a876f-22b9-11d3-aa62-00c04f8eedd8': 'ms-Exch-Modify-PF-Admin-ACL',
	'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Synchronize',
	'cffe6da4-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Modify-Public-Folder-Deleted-Item-Retention',
	'1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Manage-Topology',
	'cfc7978e-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Modify-Public-Folder-Expiry',
	'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd': 'Change-Schema-Master',
	'd03a086e-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Modify-Public-Folder-Quotas',
	'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd': 'Change-Rid-Master',
	'd0780592-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Modify-Public-Folder-Replica-List',
	'fec364e0-0a98-11d1-adbb-00c04fd8d5cd': 'Do-Garbage-Collection',
	'd74a8774-22b9-11d3-aa62-00c04f8eedd8': 'ms-Exch-Open-Send-Queue',
	'0bc1554e-0a99-11d1-adbb-00c04fd8d5cd': 'Recalculate-Hierarchy',
	'be013017-13a1-41ad-a058-f156504cb617': 'ms-Exch-Read-Metabase-Properties',
	'1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd': 'Allocate-Rids',
	'165ab2cc-d1b3-4717-9b90-c657e7e57f4d': 'ms-Exch-Recipient-Update-Access',
	'bae50096-4752-11d1-9052-00c04fc2d4cf': 'Change-PDC',
	'd0b86510-afe6-11d2-aa04-00c04f8eedd8': 'ms-Exch-Remove-PF-From-Admin-Group',
	'440820ad-65b4-11d1-a3da-0000f875ae0d': 'Add-GUID',
	'b3f9f977-552c-4ee6-9781-59280a81417b': 'ms-Exch-Send-Headers-Forest',
	'014bf69c-7b3b-11d1-85f6-08002be74fab': 'Change-Domain-Master',
	'2f7d0e23-f951-4ed0-8e71-39b6a22fa298': 'ms-Exch-Send-Headers-Organization',
	'4b6e08c0-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-Dead-Letter',
	'eb8c07ad-b5ad-49c3-831e-bc439cca4c2a': 'ms-Exch-Send-Headers-Routing',
	'4b6e08c1-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-Dead-Letter',
	'5c82f031-4e4c-4326-88e1-8c4f0cad9de5': 'ms-Exch-SMTP-Accept-Any-Recipient',
	'4b6e08c2-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-computer-Journal',
	'b857b50b-94a2-4b53-93f6-41cebd2fced0': 'ms-Exch-SMTP-Accept-Any-Sender',
	'4b6e08c3-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal',
	'1c75aca8-b56b-48b3-a021-858a29fa877b': 'ms-Exch-SMTP-Accept-Authentication-Flag',
	'06bd3200-df3e-11d1-9c86-006008764d0e': 'msmq-Receive',
	'c22841f4-96cb-498a-ac02-f9a87c74eb14': 'ms-Exch-SMTP-Accept-Authoritative-Domain-Sender',
	'06bd3201-df3e-11d1-9c86-006008764d0e': 'msmq-Peek',
	'e373fb21-d851-4d15-af23-982f09f2400b': 'ms-Exch-SMTP-Accept-Exch50',
	'06bd3202-df3e-11d1-9c86-006008764d0e': 'msmq-Send',
	'11716db4-9647-4bce-8922-1f99e526cb41': 'ms-Exch-SMTP-Send-Exch50',
	'06bd3203-df3e-11d1-9c86-006008764d0e': 'msmq-Receive-journal',
	'a18293f1-0685-4540-aa63-e32df421b3a2': 'ms-Exch-SMTP-Submit',
	'b4e60130-df3f-11d1-9c86-006008764d0e': 'msmq-Open-Connector',
	'8fc01282-006d-42b1-81e3-c0b46bed3754': 'ms-Exch-SMTP-Submit-For-MLS',
	'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply-Group-Policy',
	'd74a8762-22b9-11d3-aa62-00c04f8eedd8': 'ms-Exch-Store-Admin',
	'037088f8-0ae1-11d2-b422-00a0c968f939': 'RAS-Information',
	'9fbec2a1-f761-11d9-963d-00065bbd3175': 'ms-Exch-Store-Constrained-Delegation',
	'9923a32a-3607-11d2-b9be-0000f87a36b2': 'DS-Install-Replica',
	'd74a8766-22b9-11d3-aa62-00c04f8eedd8': 'ms-Exch-Store-Create-Named-Properties',
	'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'Change-Infrastructure-Master',
	'9fbec2a3-f761-11d9-963d-00065bbd3175': 'ms-Exch-Store-Read-Access',
	'be2bb760-7f46-11d2-b9ad-00c04f79f805': 'Update-Schema-Cache',
	'9fbec2a4-f761-11d9-963d-00065bbd3175': 'ms-Exch-Store-Read-Write-Access',
	'62dd28a8-7f46-11d2-b9ad-00c04f79f805': 'Recalculate-Security-Inheritance',
	'9fbec2a2-f761-11d9-963d-00065bbd3175': 'ms-Exch-Store-Transport-Access',
	'69ae6200-7f46-11d2-b9ad-00c04f79f805': 'DS-Check-Stale-Phantoms',
	'd74a875e-22b9-11d3-aa62-00c04f8eedd8': 'ms-Exch-Store-Visible',
	'0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment',
	'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Self-Membership',
	'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password',
	'b7b1b3dd-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Planning',
	'00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
	'9432c620-033c-4db7-8b58-14ef6d0bf477': 'Refresh-Group-Cache',
	'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send-As',
	'91d67418-0135-4acc-8d79-c08e857cfbec': 'SAM-Enumerate-Entire-Domain',
	'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive-As',
	'b7b1b3de-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Logging',
	'e48d0154-bcf8-11d1-8702-00c04fb96050': 'Public-Information',
	'b8119fd0-04f6-4762-ab7a-4986c76b3f9a': 'Domain-Other-Parameters',
	'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Validated-SPN',
	'e2a36dc9-ae17-47c3-b58b-be34c55ba633': 'Create-Inbound-Forest-Trust',
	'68b1d179-0d15-4d4f-ab71-46152e79a7bc': 'Allowed-To-Authenticate',
	'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
	'ffa6f046-ca4b-4feb-b40d-04dfee722543': 'MS-TS-GatewayAccess',
	'ba33815a-4f93-4c76-87f3-57574bff8109': 'Migrate-SID-History',
	'7726b9d5-a4b4-4288-a6b2-dce952e80a7f': 'Run-Protect-Admin-Groups-Task',
	'45ec5156-db7e-47bb-b53f-dbeb2d03c40f': 'Reanimate-Tombstones',
	'7c0e2a7c-a419-48e4-a995-10180aad54dd': 'Manage-Optional-Features',
	'2f16c4a5-b98e-432c-952a-cb388ba33f2e': 'DS-Execute-Intentions-Script',
	'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96': 'DS-Replication-Monitor-Topology',
	'280f369c-67c7-438e-ae98-1d46f3c6f541': 'Update-Password-Not-Required-Bit',
	'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire-Password',
	'05c74c5e-4deb-43b4-bd9f-86664c2a7fd5': 'Enable-Per-User-Reversibly-Encrypted-Password',
	'4ecc03fe-ffc0-4947-b630-eb672a8a9dbc': 'DS-Query-Self-Quota',
	'4125c71f-7fac-4ff0-bcb7-f09a41325286': 'DS-Set-Owner',
	'88a9933e-e5c8-4f2a-9dd7-2527416b8092': 'DS-Bypass-Quota',
	'084c93a2-620d-4879-a836-f0ae47de0e89': 'DS-Read-Partition-Secrets'
}

MoreGUID_Exchange = {
	"9D71AFC6-2C40-4C23-8CD7-E55B7D3129BD": "ms-Exch-Accepted-Domain",
	"C7B9A038-99D2-48DA-B22C-8A5412CF7A81": "ms-Exch-Accepted-Domain-Flags",
	"9A895C75-F88C-4FD0-A0DA-91FF20AFFA2C": "ms-Exch-Accepted-Domain-Name",
	"8FF54464-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Access-Control-Map",
	"901B6A04-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Access-Flags",
	"903F2D4A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Access-SSL-Flags",
	"E605672C-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Active-Directory-Connector",
	"9062F090-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ADC-Global-Names",
	"4859FB55-1924-11D3-AA59-00C04F8EEDD8": "ms-Exch-ADC-Object-Type",
	"90891630-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ADC-Options",
	"9C4D7592-EF4A-4C69-8F30-6F18CA1EC370": "ms-Exch-Add-Groups-To-Token",
	"90A814C2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Additional-DN-Map",
	"E7211F02-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Addressing-Policy",
	"F4B93A0D-F30C-44FF-AA47-E74806DBCED2": "ms-Exch-Address-List-OU",
	"E6A2C260-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Address-List-Service",
	"8A407B6E-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Address-List-Service-BL",
	"B1FCE95A-1D44-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Address-List-Service-Container",
	"9B6E9584-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Address-List-Service-Link",
	"5D0017D1-43D9-4A0E-8FBC-2ADFC96C29BF": "ms-Exch-Address-Rewrite-Configuration",
	"997F7363-A2C7-4464-9A75-220A8239CCDC": "ms-Exch-Address-Rewrite-Entry",
	"DEE53C8C-57FB-4FC3-8669-14FB9DE1D1ED": "ms-Exch-Address-Rewrite-Exception-List",
	"1156E66D-D22B-45EB-A610-B68AE27F9471": "ms-Exch-Address-Rewrite-External-Name",
	"405DAC38-C318-4635-B778-51BAAFC57BEB": "ms-Exch-Address-Rewrite-Internal-Name",
	"02E502D8-1205-489B-AA84-03B95C9A2593": "ms-Exch-Address-Rewrite-Mapping-Type",
	"90C975AE-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Admin-ACL",
	"E768A58E-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Admin-Group",
	"E7A44058-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Admin-Group-Container",
	"90EAD69A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Admin-Group-Mode",
	"E32977AE-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Admin-Groups-Enabled",
	"94E9A76C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Admin-Mailbox",
	"E7F2EDF2-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Admin-Role",
	"B644C27A-A419-40B6-A62E-180930DF5610": "ms-Exch-Admins",
	"8CC8FB0E-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Advanced-Security-Container",
	"39C9981C-2B54-48F5-BA1F-0FE2F5B3FD0F": "ms-Exch-Agent",
	"C8975410-B516-48A6-B6F8-037CF46B3C25": "ms-Exch-Agents-Flags",
	"5872299F-123A-11D3-AA58-00C04F8EEDD8": "ms-Exch-Aging-Keep-Time",
	"912B3618-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Alias-Gen-Format",
	"914EF95E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Alias-Gen-Type",
	"91705A4A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Alias-Gen-Uniqueness",
	"91941D90-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Allow-Additional-Resources",
	"63B79CF2-1F4B-4766-BA5B-814B6077640F": "ms-Exch-Allow-Enhanced-Security",
	"91B7E0D6-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Allow-Time-Extensions",
	"910C3786-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-AL-Object-Version",
	"974C99F9-33FC-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Alternate-Server",
	"2925413E-FA41-4D01-945D-A15B5D6BB965": "ms-Exch-Applies-To-Smtp-VS",
	"F7D091B1-1CED-446A-B521-563A01EAF22C": "ms-Exch-Applies-To-Smtp-VS-BL",
	"A8DF7394-C5EA-11D1-BBCB-0080C76670C0": "ms-Exch-Assistant-Name",
	"E5971321-1D3E-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Associated-AG",
	"57BDCBB8-C793-4138-8078-9FDAEB2747E9": "ms-Exch-Attachment-Filtering-Admin-Message",
	"02040A7E-00E1-4392-B3F1-4985748AB7AD": "ms-Exch-Attachment-Filtering-Attachment-Names",
	"68DDC0B3-0793-4BD1-A62F-3DB9C1F207B0": "ms-Exch-Attachment-Filtering-Content-Types",
	"F99AF030-7DF1-49CC-8D36-DE0D766F2A7B": "ms-Exch-Attachment-Filtering-Exception-Connectors-Link",
	"2253874C-6CD6-48FB-BCBB-7AEB900F08F2": "ms-Exch-Attachment-Filtering-Filter-Action",
	"637C3F3E-7E56-4DC7-9CA2-04E45EFADEE6": "ms-Exch-Attachment-Filtering-Reject-Response",
	"91D47D0E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Audit-Flags",
	"91F5DDFA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Authentication-Flags",
	"57CFB6F7-1E2C-4D3E-96DF-40208624BAFF": "ms-Exch-AuthMailDisposition",
	"D6AE616B-16C5-44CE-B272-8B923AEBE335": "ms-Exch-Authorization-Persistence",
	"ACDC8A22-36BB-424B-A167-7917255A7114": "ms-Exch-Auto-Database-Mount-After",
	"26DCF370-365E-482B-806A-48F39FCF90A0": "ms-Exch-Auto-Discover-Auth-Package",
	"22E3695C-BB35-4BF2-827A-38FA32636DC1": "ms-Exch-Auto-Discover-Cert-Principal-Name",
	"7458633C-1D26-4A9D-A037-BCF12D50A18C": "ms-Exch-Auto-Discover-Config",
	"8759DD9F-F2A3-4B14-9BAE-FB7A8337CA35": "ms-Exch-Auto-Discover-Directory-Port",
	"2DBB448A-5D85-4144-A9A5-2FC724E194A8": "ms-Exch-Auto-Discover-Flags",
	"9E7A164A-BEA7-4168-88C0-DE28C3D74200": "ms-Exch-Auto-Discover-Port",
	"FD018213-D06F-468F-ABB4-EB243C770A84": "ms-Exch-Auto-Discover-Referral-Port",
	"015568AC-FE39-44A6-9847-E818115CFC43": "ms-Exch-Auto-Discover-Server",
	"333DC37A-54BB-4E79-8D31-F9B32DF0D4EA": "ms-Exch-Auto-Discover-SPA",
	"9308D33B-9143-4A18-A2BB-381B780921DD": "ms-Exch-Auto-Discover-TTL",
	"966540A1-75F7-4D27-ACE9-3858B5DEA688": "ms-Exch-Auto-Discover-Virtual-Directory",
	"169A9E52-79F9-4E41-A6EA-45F5679384CD": "ms-Exch-Availability-Access-Method",
	"2B02D9AF-BD14-42D0-8F37-7AA5CD7BEEF9": "ms-Exch-Availability-Address-Space",
	"E676FEC3-DCD0-4565-BAEA-E25D08698AC1": "ms-Exch-Availability-Config",
	"3E3EA45B-3573-45BE-969D-FF5B5079C969": "ms-Exch-Availability-Foreign-Connector-Domain",
	"8776D09E-D7AE-44CC-BD4F-ABB9CB8DCD22": "ms-Exch-Availability-Foreign-Connector-Type",
	"63C3D4A1-F208-49D1-AD5E-AE733901229A": "ms-Exch-Availability-Foreign-Connector-Virtual-Directory",
	"E1930418-FC4F-4485-84D0-543174CB5DD7": "ms-Exch-Availability-Forest-Name",
	"480799EA-C8B2-404A-84B4-0FD7363D08D0": "ms-Exch-Availability-Org-Wide-Account",
	"2BB58427-B5FF-4B63-B671-7C1D0F46B2D7": "ms-Exch-Availability-Per-User-Account",
	"02514E6A-1899-4AB5-80EE-910018540BE3": "ms-Exch-Availability-User-Name",
	"97C84796-00DA-4290-90F7-8FD82EB6645A": "ms-Exch-Availability-User-Password",
	"DE48F169-67B7-46E5-9E5F-E5F227D17D73": "ms-Exch-Availability-Use-Service-Account",
	"923B022C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Available-Servers",
	"B4B283B6-0C3F-4A59-9E50-BE9026228231": "ms-Exch-BackEnd-VDir-URL",
	"93D051F0-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Background-Threads",
	"CF43E549-2AE1-410F-B896-02E40B934373": "ms-Exch-Bar-Message-Class",
	"D8782C34-46CA-11D3-AA72-00C04F8EEDD8": "ms-Exch-Base-Class",
	"94262698-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Basic-Authentication-Domain",
	"944C4C38-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Bridgeheaded-Local-Connectors-DN-BL",
	"946DAD24-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Bridgeheaded-Remote-Connectors-DN-BL",
	"75447978-3752-4256-A89F-B4DFEBAE9A32": "ms-Exch-CalCon-Client-Wait",
	"73B41A3E-68B0-45A1-9E30-697B6D19AEE6": "ms-Exch-CalCon-Providers",
	"5EBB881A-19D4-4526-B6F7-CC46D9AA1869": "ms-Exch-CalCon-Query-Window",
	"22BF39B6-7528-412C-B277-AA268DB43960": "ms-Exch-CalCon-Refresh-Interval",
	"33B45526-8E8B-4679-97C3-4EEFF39C7FBD": "ms-Exch-CalCon-Target-SiteDN",
	"922180DA-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Calendar-Connector",
	"948F0E10-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-CA-Schema-Policy",
	"94ABAA48-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Catalog",
	"94CAA8DA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ccMail-ADE-Prop",
	"B8D47E43-4B78-11D3-AA75-00C04F8EEDD8": "ms-Exch-ccMail-Connect-As-Password",
	"B8D47E3C-4B78-11D3-AA75-00C04F8EEDD8": "ms-Exch-ccMail-Connect-As-Userid",
	"E85710B6-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-ccMail-Connector",
	"950B0858-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ccMail-Filter-Type",
	"952A06EA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ccMail-Import-Export-Version",
	"9546A322-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ccMail-Keep-Forward-History",
	"4634194C-4A93-11D3-AA73-00C04F8EEDD8": "ms-Exch-ccMail-Password",
	"95633F5A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ccMail-PO-Name",
	"98ED3CF2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ccMail-PO-Path",
	"98CE3E60-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Certificate",
	"E8977034-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Certificate-Information",
	"8CAC5ED6-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Access",
	"98AF3FCE-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Admin-Message",
	"E8D0A8A4-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Chat-Ban",
	"9890413C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Ban-Mask",
	"959C77CA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Ban-Reason",
	"95B91402-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Broadcast-Address",
	"E902BA06-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Chat-Channel",
	"95D81294-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Auto-Create",
	"95F4AECC-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Flags",
	"96114B04-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Host-Key",
	"962DE73C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Join-Message",
	"964A8374-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Key",
	"96671FAC-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Language",
	"9683BBE4-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-LCID",
	"96A0581C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Limit",
	"96BA91FA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Mode",
	"96D72E32-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Name",
	"96F3CA6A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Owner-Key",
	"9712C8FC-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Part-Message",
	"972D02DA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-PICS",
	"97499F12-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Subject",
	"97663B4A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Channel-Topic",
	"9782D782-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Class-Ident-Mask",
	"97A1D614-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Class-IP",
	"8090A000-1234-11D3-AA58-00C04F8EEDD8": "ms-Exch-Chat-Class-Restrictions",
	"8090A006-1234-11D3-AA58-00C04F8EEDD8": "ms-Exch-Chat-Class-Scope-Type",
	"97BE724C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Client-Port",
	"97DB0E84-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-DNS-Reverse-Mode",
	"97FA0D16-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Duration",
	"98190BA8-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Enable-Anonymous",
	"9835A7E0-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Enable-Authenticated",
	"3B9D8DE5-2D93-11D3-AA6B-00C04F8EEDD8": "ms-Exch-Chat-Extensions",
	"987142AA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Input-Flood-Limit",
	"9969373A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Max-Anonymous",
	"9985D372-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Max-Connections",
	"2AC57E6B-F737-4E41-8386-7295DDBE05E6": "ms-Exch-Chat-Max-Connections-Per-IP",
	"99A4D204-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Max-Memberships",
	"3DE37B23-2789-4DF7-B51F-F920CE544458": "ms-Exch-Chat-Max-Octets-To-Mask",
	"99E2CF28-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Message-Lag",
	"99FF6B60-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-MOTD",
	"E934CB68-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Chat-Network",
	"917CFE98-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Network-Mode",
	"9A1E69F2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Network-Name",
	"9A3D6884-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Nick-Delay",
	"9A5C6716-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Output-Saturation",
	"9A7B65A8-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Ping-Delay",
	"9A9A643A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Protection-Level",
	"E9621816-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Chat-Protocol",
	"9AB70072-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Server-Port",
	"9AD39CAA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Start-Time",
	"9AF29B3C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Chat-Title",
	"E9A0153A-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Chat-User-Class",
	"EA5ED15A-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Chat-Virtual-Network",
	"9B309860-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Child-Sync-Agreements",
	"035DA50E-1A9E-11D3-AA59-00C04F8EEDD8": "ms-Exch-CI-Available",
	"CEC44725-22AE-11D3-AA62-00C04F8EEDD8": "ms-Exch-CI-Location",
	"035DA4FD-1A9E-11D3-AA59-00C04F8EEDD8": "ms-Exch-CI-Rebuild-Schedule",
	"035DA507-1A9E-11D3-AA59-00C04F8EEDD8": "ms-Exch-CI-Rebuild-Style",
	"035DA4F8-1A9E-11D3-AA59-00C04F8EEDD8": "ms-Exch-CI-Update-Schedule",
	"035DA502-1A9E-11D3-AA59-00C04F8EEDD8": "ms-Exch-CI-Update-Style",
	"2D2F066E-01B7-4206-84CF-1C5C3355B752": "ms-Exch-Cluster-Replication-Ordered-Prefixes",
	"F390E0F2-195C-4786-A231-ECC35C4223D0": "ms-Exch-Cluster-Storage-Type",
	"8A5852F2-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Computer-Link",
	"ED2C752C-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Computer-Policy",
	"ED7FE77A-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Conference-Container",
	"628F0513-88F6-4CEF-9DE4-B367EB7E8383": "ms-Exch-Conference-Mailbox",
	"9423EC2C-383B-44B2-8913-AB79AC609BD4": "ms-Exch-Conference-Mailbox-BL",
	"EDDCE330-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Conference-Site",
	"8CFD6ECA-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Conference-Zone",
	"8D1A0B02-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Conference-Zone-BL",
	"D03D6858-06F4-11D2-AA53-00C04FD7D83A": "ms-Exch-Configuration-Container",
	"EE64C93A-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Connection-Agreement",
	"89652316-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Connector",
	"EEE325DC-A980-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Connectors",
	"9B8D9416-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Connector-Type",
	"006C91DA-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Container",
	"AB3A1ACC-1DF5-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Content-Config-Container",
	"91462882-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Controlling-Zone",
	"9BAC92A8-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Convert-To-Fixed-Font",
	"25568433-65F1-463E-89BE-951D3184AA57": "ms-Exch-Copy-EDB-File",
	"9C098E5E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Correlation-Attribute",
	"50C7D2B3-E584-4913-9E1E-8C8CA03C5186": "ms-Exch-Cost",
	"00AA8EFE-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-CTP",
	"9C288CF0-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-CTP-Class-GUID",
	"9C478B82-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-CTP-Frame-Hint",
	"9C6427BA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-CTP-Property-Schema",
	"9C8588A6-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-CTP-Provider-GUID",
	"9CA48738-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-CTP-Provider-Name",
	"8AA962E6-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-CTP-Require-CMS-Authentication",
	"9CC385CA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-CTP-Snapin-GUID",
	"53436E7C-17D9-40F4-954D-C34D013E9C16": "ms-Exch-Current-Server-Roles",
	"00E629C8-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Custom-Attributes",
	"E24D7A90-439D-11D3-AA72-00C04F8EEDD8": "ms-Exch-Custom-Proxy-Addresses",
	"372FADFF-D0B6-4552-8057-F3A0D2C706A7": "ms-Exch-Database-Being-Restored",
	"14F27149-BA76-4AEE-BAC8-FCED38FDFF9D": "ms-Exch-Database-Created",
	"9CE2845C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Database-Session-Addend",
	"9D0647A2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Database-Session-Increment",
	"EB17E0A3-6BF3-411F-923D-A8A2041D9CC1": "ms-Exch-Data-Loss-For-Auto-Database-Mount",
	"61C47260-454E-11D3-AA72-00C04F8EEDD8": "ms-Exch-Data-Path",
	"847584C2-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Default-Admin-Group",
	"9D22E3DA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Default-Domain",
	"6267667C-CF34-407D-BA11-7CC8CC68CA1B": "ms-Exch-Default-Load-File",
	"8BB46A46-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Default-Logon-Domain",
	"9D41E26C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Delivery-Order",
	"9D60E0FE-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Dereference-Aliases",
	"9D8241EA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Dest-BH-Address",
	"9D9EDE22-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Destination-RG-DN",
	"8C221672-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Dir-Browse-Flags",
	"9DBDDCB4-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Dirsync-Filters",
	"8E11FF92-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Dirsync-Schedule",
	"8E2E9BCA-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Dirsync-Style",
	"372D6CDE-38C7-47B6-A3DA-BE4648124EC0": "ms-Exch-Disable-UDG-Conversion",
	"3DF30250-38A7-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Discussion-Folder",
	"9E1AD86A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Do-Full-Replication",
	"AB3A1AD1-1DF5-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Domain-Content-Config",
	"6491CF09-4D5A-465F-A7D9-BB6524FE0698": "ms-Exch-Domain-Content-Config-Flags",
	"0D5AABA3-B593-4256-88DC-A0DB2D2FFEEC": "ms-Exch-Domain-Global-Group-Guid",
	"D059B789-3E9E-4B8F-BEFE-DB62BB580885": "ms-Exch-Domain-Global-Group-Sid",
	"8AC39CC4-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Domain-Link",
	"3BF8FFC0-6492-4AF4-B2BF-4F9FDB423425": "ms-Exch-Domain-Local-Group-Guid",
	"D27EB1E5-A06C-4151-B789-59EABBA8EDCA": "ms-Exch-Domain-Local-Group-Sid",
	"9E39D6FC-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-DownGrade-Multipart-Signed",
	"974C99DA-33FC-11D3-AA6E-00C04F8EEDD8": "ms-Exch-DS2MB-Options",
	"275DBE59-53B3-401D-88CC-9887AD198FAA": "ms-Exch-DSN-Flags",
	"CAD3F52A-2888-4DA9-9BCB-A335FCA35C14": "ms-Exch-DSN-Message",
	"61D591AE-C2E6-4886-9267-1D262BB8C363": "ms-Exch-DSN-Send-Copy-To-Admin",
	"40236C62-0CD2-48E5-A5D6-005B370328BA": "ms-Exch-DSN-Text",
	"018849B0-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Dynamic-Distribution-List",
	"763D0EF9-BD92-41F9-AB34-7E329DB76EE3": "ms-Exch-Dynamic-DL-BaseDN",
	"E1B6D32C-6BAC-48DA-A313-2B58AE1C45CE": "ms-Exch-Dynamic-DL-Filter",
	"9E58D58E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-EDB-File",
	"9E7A367A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-EDB-Offline",
	"5150729B-DFD0-4F84-AA9E-5D1ADC335976": "ms-Exch-Edge-Sync-Adam-Ldap-Port",
	"BB262B78-4564-43B2-96F1-378828F71A14": "ms-Exch-Edge-Sync-Adam-SSL-Port",
	"B71519A3-1465-4B55-BDFB-E144BF7A7682": "ms-Exch-Edge-Sync-Credential",
	"061D0240-2AC1-46C9-8252-66E52281F892": "ms-Exch-Edge-Sync-Lease",
	"050F9910-3408-493E-96E1-CDC47EF18384": "ms-Exch-Edge-Sync-Status",
	"08C2246F-FE2E-432F-B464-4D1C8113BCC2": "ms-Exch-ELC-Admin-Description-Localized",
	"4ADAD576-F27C-4754-B5DB-D2BECEBABEAD": "ms-Exch-ELC-Audit-Log-Directory-Size-Limit",
	"29DECCD9-2FA9-4F30-ABC1-874F8F44F925": "ms-Exch-ELC-Audit-Log-File-Age-Limit",
	"BD345BF8-AEE7-4851-93A9-970607C15632": "ms-Exch-ELC-Audit-Log-File-Size-Limit",
	"D4B87AE0-F107-4A57-A303-EFB5C49BF83D": "ms-Exch-ELC-Audit-Log-Path",
	"52A4CBFC-5808-43D4-94F7-DE19104FE215": "ms-Exch-ELC-Auto-Copy-Address-Link",
	"BC3D75AC-F92D-40CD-A223-37B43B4232B8": "ms-Exch-ELC-Content-Settings",
	"97BCE56B-C573-4850-82A2-E21E20641532": "ms-Exch-ELC-Expiry-Action",
	"FF0EF8EF-CC6B-42BA-90D3-D37E58B3311D": "ms-Exch-ELC-Expiry-Age-Limit",
	"62221A15-CBAF-4EBB-9B9C-74F59E1DA8A9": "ms-Exch-ELC-Expiry-Destination-Link",
	"34101173-1670-48A5-9928-648DDDBB7000": "ms-Exch-ELC-Expiry-Suspension-End",
	"3BD0B7B0-EE14-4B4F-BC04-FBB2E441C226": "ms-Exch-ELC-Expiry-Suspension-Start",
	"2AA7C06E-1666-4CAB-AA0B-2C7221F91051": "ms-Exch-ELC-Flags",
	"FDB7DDB7-8D54-4FA8-9728-33DA6C89BFE4": "ms-Exch-ELC-Folder",
	"248BA72B-8E16-4EFB-9127-E307E6E875AC": "ms-Exch-ELC-Folder-BL",
	"7111E513-9E92-4171-9174-4F866C2D7369": "ms-Exch-ELC-Folder-Link",
	"6F859570-DB5C-4563-8842-DDD84DD5DE23": "ms-Exch-ELC-Folder-Name",
	"176D1E13-4E1E-405C-94C7-294ED2B737E6": "ms-Exch-ELC-Folder-Name-Localized",
	"D104E7E1-52F3-4618-8E8C-8DDC911A31D5": "ms-Exch-ELC-Folder-Quota",
	"0316E35A-2393-4410-B6FE-9ABD7041482A": "ms-Exch-ELC-Folder-Type",
	"98A01A24-2FD8-4E38-A418-6B1498C0501C": "ms-Exch-ELC-Label",
	"3F8950E3-DB72-40E3-8AE8-3107FA5E6EED": "ms-Exch-ELC-Mailbox-Flags",
	"3D48CC67-2F1D-40B0-8BBA-9794D4EFE146": "ms-Exch-ELC-Message-Class",
	"F57E74A8-0866-418D-8340-239FCEFD83D9": "ms-Exch-ELC-Organizational-Root-URL",
	"4C41DC66-8C6B-4DA0-B482-5349AF59D962": "ms-Exch-ELC-Schedule",
	"9A56980F-283C-4F86-8395-23011350600C": "ms-Exch-Enable-Internal-Evaluator",
	"3A633F17-5194-11D3-AA77-00C04F8EEDD8": "ms-Exch-Encode-SMTP-Relay",
	"5DC055FC-5C3F-4A6F-A34A-4DBCB68E2AD0": "ms-Exch-Encrypted-Anonymous-Password",
	"08C63250-0DF6-405D-8907-0312DD1AA145": "ms-Exch-Encrypted-Password",
	"DCBC61E9-9279-44D1-B494-25562659DB75": "ms-Exch-Encrypted-Password-2",
	"5A499BCD-56CB-4896-B7BF-365C75DA7F2D": "ms-Exch-Encrypted-TLS-P12",
	"CDDE1C9E-D38A-458E-83D0-2E5EC8E379AB": "ms-Exch-Encrypted-Transport-Service-KPK",
	"2D09783D-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Assert-Action",
	"2D097845-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Base-Name",
	"D19C67F8-A0EB-432A-BEDD-AF10CD7DA25C": "ms-Exch-ESE-Param-Cached-Closed-Tables",
	"9EB8339E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Cache-Size",
	"9ED73230-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Cache-Size-Max",
	"2D097841-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Cache-Size-Min",
	"2D09785A-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Checkpoint-Depth-Max",
	"9EF8931C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Circular-Log",
	"2D097849-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Commit-Default",
	"B8CB4A11-6962-4C27-8239-2F3228BCBB0B": "ms-Exch-ESE-Param-Copy-Log-File-Path",
	"29D6828A-1BDC-4B07-9DE8-5252FDFFCD98": "ms-Exch-ESE-Param-Copy-System-Path",
	"2D09784D-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Db-Extension-Size",
	"2D097838-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Enable-Index-Checking",
	"2D097833-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Enable-Online-Defrag",
	"2D097828-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Enable-Sorted-Retrieve-Columns",
	"9F19F408-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Event-Source",
	"02E831DA-2F29-11D3-AA6C-00C04F8EEDD8": "ms-Exch-ESE-Param-Global-Min-Ver-Pages",
	"9F38F29A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Log-Buffers",
	"9F5A5386-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Log-Checkpoint-Period",
	"9F795218-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Log-File-Path",
	"9F9AB304-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Log-File-Size",
	"9FBE764A-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Log-Waiting-User-Max",
	"2D097830-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Max-Cursors",
	"9FDFD736-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Max-Open-Tables",
	"9FFED5C8-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Max-Sessions",
	"2D09782C-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Max-Temporary-Tables",
	"A02036B4-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Max-Ver-Pages",
	"2D097855-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Page-Fragment",
	"2D097851-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-ESE-Param-Page-Temp-DB-Min",
	"A04197A0-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Preferred-Max-Open-Tables",
	"A062F88C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Preferred-Ver-Pages",
	"92ABC93E-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Start-Flush-Threshold",
	"92C6031C-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Stop-Flush-Threshold",
	"A086BBD2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-System-Path",
	"A0A5BA64-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Temp-Path",
	"A0C71B50-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Wait-Log-Flush",
	"A0E619E2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-ESE-Param-Zero-Database-During-Backup",
	"027E6F41-6161-431D-9830-22DE0E8E1393": "ms-Exch-Event-History-Retention-Period",
	"01A9AA9C-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Exchange-Server",
	"A1051874-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Exchange-Server-Link",
	"E497942F-1D42-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Exchange-Server-Policy",
	"58B55FB8-CE43-4987-B313-BF94ABD81DB3": "ms-Exch-Exchange-Server-Recipient",
	"24D808F5-2439-11D3-AA66-00C04F8EEDD8": "ms-Exch-Exchange-Site",
	"A1241706-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Expansion-Server-Name",
	"2436AC3E-1D4E-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Export-Containers-BL",
	"3B7EA364-1D4D-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Export-Containers-Linked",
	"A14577F2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Export-DLs",
	"33570C36-9686-45E3-9683-CD83BB7538DA": "ms-Exch-External-Authentication-Methods",
	"D430D4C4-0AE2-49B2-91DF-378A005EB36A": "ms-Exch-External-Host-Name",
	"75617923-18B4-4166-9971-E9E788B314A1": "ms-Exch-External-OOF-Options",
	"A166D8DE-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-FB-URL",
	"8A8F2908-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-First-Instance",
	"5070257A-85B7-4ED4-B2E2-51F726684C58": "ms-Exch-Folder-Affinity-Custom",
	"3592BC80-1117-4962-AA50-38C6E69BBB91": "ms-Exch-Folder-Affinity-List",
	"E5FBFBC3-A59F-4B30-88C1-DFD632833CB3": "ms-Exch-Foreign-Forest-FQDN",
	"6696C047-41BD-4C2F-9AAE-46B7AA698475": "ms-Exch-Foreign-Forest-Org-Admin-USG-Sid",
	"840EA0DD-AE15-4B37-B6D3-C8A7BC5E46E9": "ms-Exch-Foreign-Forest-Public-Folder-Admin-USG-Sid",
	"155B65D1-7180-446A-B19E-846B931EB009": "ms-Exch-Foreign-Forest-Read-Only-Admin-USG-Sid",
	"ED09A363-0A6F-47FF-8361-F16C8E595FF5": "ms-Exch-Foreign-Forest-Recipient-Admin-USG-Sid",
	"2A38CE3D-73AD-46C7-BCB0-22ED3514F555": "ms-Exch-Foreign-Forest-Server-Admin-USG-Sid",
	"E32977CD-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Generic-Policy",
	"E32977C3-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Generic-Policy-Container",
	"A1D6E764-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Grace-Period-After",
	"A1F84850-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Grace-Period-Prior",
	"91EAAAC4-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-GroupWise-Connector",
	"C7E96933-BD80-44A2-A535-EC744EA5F54F": "ms-Exch-GWise-API-Gateway",
	"3B9D8DEA-2D93-11D3-AA6B-00C04F8EEDD8": "ms-Exch-GWise-API-Gateway-Path",
	"3B9D8DEE-2D93-11D3-AA6B-00C04F8EEDD8": "ms-Exch-GWise-Filter-Type",
	"3B9D8DF3-2D93-11D3-AA6B-00C04F8EEDD8": "ms-Exch-GWise-Foreign-Domain",
	"3B9D8DF9-2D93-11D3-AA6B-00C04F8EEDD8": "ms-Exch-GWise-Password",
	"3B9D8E00-2D93-11D3-AA6B-00C04F8EEDD8": "ms-Exch-GWise-User-Id",
	"03C165C8-9BD9-4934-8AE6-06BAA7898D02": "ms-Exch-Has-Local-Copy",
	"A21C0B96-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Hide-From-Address-Lists",
	"A23FCEDC-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Home-Public-MDB",
	"F649DEED-1C26-4ED4-B639-F333A4850BC2": "ms-Exch-Home-Routing-Group",
	"A2612FC8-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Home-Routing-Group-DN-BL",
	"A284F30E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Home-Server-Name",
	"A2A3F1A0-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Home-Sync-Service",
	"A8DF7407-C5EA-11D1-BBCB-0080C76670C0": "ms-Exch-House-Identifier",
	"A2E915D2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-IFS-Private-Enabled",
	"A30A76BE-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-IFS-Private-Name",
	"A32BD7AA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-IFS-Public-Enabled",
	"A34D3896-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-IFS-Public-Name",
	"06551010-2845-11D3-AA68-00C04F8EEDD8": "ms-Exch-IM-ACL",
	"CBBD3752-B8D8-47DC-92EE-AB488C1AF969": "ms-Exch-IM-Address",
	"5E26DD2A-9B0A-4219-8183-20AD44F5CBDF": "ms-Exch-IMAP-OWA-URL-Prefix-Override",
	"A4394164-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-IM-DB-Log-Path",
	"A45AA250-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-IM-DB-Path",
	"9F116EBE-284E-11D3-AA68-00C04F8EEDD8": "ms-Exch-IM-Firewall",
	"06550FFC-2845-11D3-AA68-00C04F8EEDD8": "ms-Exch-IM-Firewall-Type",
	"9F116EB8-284E-11D3-AA68-00C04F8EEDD8": "ms-Exch-IM-Global-Settings-Container",
	"807B6084-439B-11D3-AA72-00C04F8EEDD8": "ms-Exch-IM-Host-Name",
	"0655100B-2845-11D3-AA68-00C04F8EEDD8": "ms-Exch-IM-IP-Range",
	"8E7A93A3-5A7C-11D3-AA78-00C04F8EEDD8": "ms-Exch-IM-Meta-Physical-URL",
	"8E7A93A8-5A7C-11D3-AA78-00C04F8EEDD8": "ms-Exch-IM-Physical-URL",
	"9FF15C4C-1EC9-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Import-Container-Linked",
	"06551002-2845-11D3-AA68-00C04F8EEDD8": "ms-Exch-IM-Proxy",
	"028502F4-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-IM-Recipient",
	"8D6B1AF6-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-IM-Server-Hosts-Users",
	"8D3444E0-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-IM-Server-IIS-Id",
	"8D4E7EBE-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-IM-Server-Name",
	"41E8FD82-8F37-4E56-A44A-33A3E6B7526C": "ms-Exch-IM-Virtual-Server",
	"A64CEDCA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Incoming-Connection-Timeout",
	"1D80475F-E7B4-4005-AF4D-82BCBF407C3C": "ms-Exch-Inconsistent-State",
	"031B371A-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Information-Store",
	"99F5865D-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Installed-Components",
	"8A23DF36-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Install-Path",
	"A86C1D2A-2EF8-4096-9D89-D3DE2B297F02": "ms-Exch-Internal-Authentication-Methods",
	"50B874EA-D760-47AA-A89A-0E7D276F9926": "ms-Exch-Internal-Host-Name",
	"7A063128-5AEB-42A5-8C90-A46B333915DE": "ms-Exch-Internal-NLB-Bypass-Host-Name",
	"310DB99F-6369-4010-9818-EAFCB2070181": "ms-Exch-Internal-SMTP-Servers",
	"A670B110-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Internet-Name",
	"3836C80B-8CEE-4413-9E65-E937C1AED10F": "ms-Exch-Inter-Org-Address-Type",
	"8B46BE1A-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-IP-Address",
	"99F5866D-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Ip-Conf-Container",
	"A68FAFA2-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-IP-Security",
	"A6B1108E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Is-Bridgehead-Site",
	"910F526C-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Is-Config-CA",
	"7B4FC83B-7B2A-4267-9AA2-B824DCF08FC3": "ms-Exch-Journaling-Report-NDR-To",
	"B94635D2-1400-457D-849E-B480141B9F2B": "ms-Exch-Journaling-Rules-Link",
	"8CE334EC-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Key-Management-Server",
	"16775820-47F3-11D1-A9C3-0000F80367C1": "ms-Exch-LabeledURI",
	"B412B288-8C00-40BD-9B3A-3D6C19ED02E9": "ms-Exch-Last-Applied-Recipient-Filter",
	"974C99E1-33FC-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Legacy-Account",
	"974C99EA-33FC-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Legacy-Domain",
	"974C99F2-33FC-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Legacy-PW",
	"A6F634C0-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-List-Public",
	"AB3A1AC7-1DF5-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Local-Domains",
	"A738F698-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Locales",
	"A7153352-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Local-Name",
	"7ACF216D-1F42-48EC-B1BB-6CA281FE5B00": "ms-Exch-Logon-ACL",
	"8BCC41CA-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Logon-Method",
	"A75A5784-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Log-Type",
	"D72941BA-FFD0-4D8E-BB85-97713440C8A3": "ms-Exch-Mailbox-Folder-Set",
	"9333AF48-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Mailbox-Guid",
	"829122D7-25B1-4BE6-A2E3-D8453C950938": "ms-Exch-Mailbox-Manager-Activation-Schedule",
	"9EA95949-7D74-49CD-AF09-3DB0870E535E": "ms-Exch-Mailbox-Manager-Activation-Style",
	"9A6B371E-A3E7-4266-9B7B-2CE454336F90": "ms-Exch-Mailbox-Manager-Admin-Mode",
	"CD63DB2C-8AA9-4A14-941B-1B59FDCAAFBD": "ms-Exch-Mailbox-Manager-Age-Limit",
	"8681F0BC-24D6-4D58-BC16-62F73CD5BEDB": "ms-Exch-Mailbox-Manager-Custom-Message",
	"A57CF645-4B12-4EE4-A6EB-FCE022068FFD": "ms-Exch-Mailbox-Manager-Folder-Settings",
	"0044D40C-6A24-4B57-ABCE-F555CC724C8E": "ms-Exch-Mailbox-Manager-Keep-Message-Classes",
	"9BD7499B-282B-4EB6-A40E-7D044D896741": "ms-Exch-Mailbox-Manager-Mode",
	"36F94FCC-EBBB-4A32-B721-1CAE42B2DBAB": "ms-Exch-Mailbox-Manager-Policy",
	"445791FB-E6FC-48DD-AAD5-32E32C9059D9": "ms-Exch-Mailbox-Manager-Report-Recipient",
	"D2888DB3-2B0D-4D6A-831E-4EFDFC036584": "ms-Exch-Mailbox-Manager-Send-User-Notification-Mail",
	"92D9302B-76BD-4156-95A1-F5B6A1463EB4": "ms-Exch-Mailbox-Manager-Size-Limit",
	"1563EAE5-3AC1-4274-9E59-7D2FCC836F82": "ms-Exch-Mailbox-Manager-Size-Limit-Enabled",
	"9EC3CCAC-09FA-4A22-869F-9144258D230D": "ms-Exch-Mailbox-Manager-User-Message-Body",
	"33795ABB-57BA-43EC-9F7E-A4601C2E4D4F": "ms-Exch-Mailbox-Manager-User-Message-Footer",
	"FBCFFEFE-8916-4CE6-AC76-EAB226FE5440": "ms-Exch-Mailbox-Manager-User-Message-Header",
	"F53CBA52-5B04-48DB-A27A-B69D1F8FA9D0": "ms-Exch-Mailbox-OAB-Virtual-Directories-BL",
	"30D266DC-5282-4128-ABA8-B458E4672FA1": "ms-Exch-Mailbox-OAB-Virtual-Directories-Link",
	"79532694-6170-4D79-8444-76B1D2E10389": "ms-Exch-Mailbox-Recipient-Template",
	"7B4A7A8A-1876-11D3-AA59-00C04F8EEDD8": "ms-Exch-Mailbox-Retention-Period",
	"791999F9-667A-4ACA-9B48-305AC2D75CF5": "ms-Exch-Mailbox-Role-Flags",
	"934DE926-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Mailbox-Security-Descriptor",
	"93CFE86D-C7D0-4108-B117-9CC72908EE6E": "ms-Exch-Mailbox-Template-BL",
	"E7629335-2B5F-4593-8656-85239A9C46F6": "ms-Exch-Mailbox-Template-Link",
	"FC1FFD10-AE3F-466C-87C7-518B91DADBD0": "ms-Exch-Mailbox-Url",
	"E2885C16-2D7B-4312-BAD3-AC86E4B2DDFC": "ms-Exch-Mail-Gateway-Flags",
	"03652000-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Mail-Storage",
	"8FA76EF0-25D7-11D3-AA68-00C04F8EEDD8": "ms-Exch-Maintenance-Schedule",
	"8FA76EF6-25D7-11D3-AA68-00C04F8EEDD8": "ms-Exch-Maintenance-Style",
	"E32977BE-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Mandatory-Attributes",
	"E1AF1477-39F6-4FA7-86C4-68DECB302E2C": "ms-Exch-Master-Account-History",
	"936A855E-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Master-Account-Sid",
	"944D04C4-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Master-Service",
	"946C0356-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Master-Service-BL",
	"D15BA867-0B2B-474C-8554-E7A3BCDDCBC3": "ms-Exch-Max-Blocked-Senders",
	"1529CF69-2FDB-11D3-AA6D-00C04F8EEDD8": "ms-Exch-Max-Cached-Views",
	"A7C33EFC-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Max-Connections",
	"0EFA2537-CFBA-4EE4-B2DE-E47A1EDC9942": "ms-Exch-Max-Dumpster-Size-Per-Storage-Group",
	"A3FF7A18-9C6D-4CC4-B92E-DAF06E2C56DD": "ms-Exch-Max-Dumpster-Time",
	"99F58668-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Max-Extension-Time",
	"A8B8D132-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Maximum-Recurring-Instances",
	"A8DA321E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Maximum-Recurring-Instances-Months",
	"A808632E-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Max-Incoming-Connections",
	"99F58663-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Max-Participants",
	"A82E88CE-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Max-Pool-Threads",
	"3EF2A80E-EA82-421B-8A62-A12543C34141": "ms-Exch-Max-Restore-Storage-Groups",
	"417ADA0B-58F3-48E8-A283-9C9CD3C4B4B7": "ms-Exch-Max-Safe-Senders",
	"A84FE9BA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Max-Storage-Groups",
	"A8714AA6-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Max-Stores-Per-Group",
	"C638458C-E40B-43C2-96D7-6DBFA2FA3CF1": "ms-Exch-Max-Stores-Total",
	"A8950DEC-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Max-Threads",
	"038680EC-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-MCU",
	"03AA4432-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-MCU-Container",
	"BD062BC7-CE32-4690-8B8E-5C63B816B516": "ms-Exch-MCU-Hosts-Sites",
	"B0AB8D77-2486-467D-A331-3E3524438A57": "ms-Exch-MCU-Hosts-Sites-BL",
	"03D069D2-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-MDB",
	"B04EBC2C-F0EA-425F-B367-85A56CFDEE79": "ms-Exch-MDB-Rules-Quota",
	"A921B8AA-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Member-Base-DN",
	"A9457BF0-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Member-Filter",
	"A823C5E7-6BBA-4D6C-802C-98756F2BE468": "ms-Exch-Message-Classification",
	"402585CA-A3CE-4515-9184-17F9F41C8582": "ms-Exch-Message-Classification-Banner",
	"78D10F2D-F9D1-4CE8-9DCE-8ABF63DF3676": "ms-Exch-Message-Classification-Confidentiality-Action",
	"F0BE958E-D80F-4EC4-BD35-F836AFAC3F11": "ms-Exch-Message-Classification-Display-Precedence",
	"0CD10EAF-DF05-4E68-A619-F792215ADA65": "ms-Exch-Message-Classification-Flags",
	"5484DFFC-F788-4A63-ADDF-EC7B9BC496D9": "ms-Exch-Message-Classification-ID",
	"2931B382-59CF-43D4-8E15-6398DE9B2B67": "ms-Exch-Message-Classification-Integrity-Action",
	"D3FEDCFC-7975-4B31-B0B1-1005E1B27F37": "ms-Exch-Message-Classification-Locale",
	"C5915811-CD8C-46C0-B721-E1DE18DE5F11": "ms-Exch-Message-Classification-URL",
	"CE6819FD-7C75-44FA-B3EE-073CDEFA8902": "ms-Exch-Message-Classification-Version",
	"AB3A1AD7-1DF5-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Message-Delivery-Config",
	"3DEEF1F9-6E2B-430B-BD88-4034086212FD": "ms-Exch-Message-Hygiene-Bitmask",
	"E6EFE991-5D0D-4940-BD85-A5F76C14A3E8": "ms-Exch-Message-Hygiene-Blocked-Domain",
	"C7DFBA1D-1A2F-4FE3-9B75-DA4348F4E88C": "ms-Exch-Message-Hygiene-Blocked-Domain-And-Subdomains",
	"02D3A8DB-36AA-4330-8942-CFAC2074C87B": "ms-Exch-Message-Hygiene-Blocked-Recipient",
	"23C20671-7480-42AF-B7F3-AC5905736798": "ms-Exch-Message-Hygiene-Blocked-Sender",
	"868A133B-066E-447C-9044-284B0326D58E": "ms-Exch-Message-Hygiene-Blocked-Sender-Action",
	"A33BB655-543B-44AF-A137-C6070E807959": "ms-Exch-Message-Hygiene-Bypassed-Recipient",
	"861E2F06-A25E-4837-9507-6DD6F721DCE1": "ms-Exch-Message-Hygiene-Bypassed-Sender-Domain",
	"66240C5B-3E49-421F-B4AF-AAD54C9BD3AA": "ms-Exch-Message-Hygiene-Bypassed-Sender-Domains",
	"4ABB7FE2-84F5-4C94-A3F2-1ACC9BD6883A": "ms-Exch-Message-Hygiene-Bypassed-Senders",
	"B7850FF9-A975-4CC0-B358-B866293C42BC": "ms-Exch-Message-Hygiene-Content-Filter-Config",
	"DA9B199D-0DA7-405B-B464-AF854CD17582": "ms-Exch-Message-Hygiene-Content-Filter-Location",
	"28754B0E-B2A9-4914-9F70-6F29A04C0B78": "ms-Exch-Message-Hygiene-Custom-Weight-Entry",
	"0214E331-2ADC-4048-952D-5772BC7BC430": "ms-Exch-Message-Hygiene-Delay-Hours",
	"398C04E2-147B-44EB-A97F-7C871D5DBB12": "ms-Exch-Message-Hygiene-Flags",
	"5BC77AE9-CC06-4EB1-B434-D00C47FE8D53": "ms-Exch-Message-Hygiene-IP-Address",
	"A287133A-054A-4E8A-8E2E-C209C95EA24B": "ms-Exch-Message-Hygiene-IP-Allow-List-Config",
	"0A4E0D5A-EC87-4E80-8028-735ED0F7AF4A": "ms-Exch-Message-Hygiene-IP-Allow-List-Provider",
	"8ECE3E9C-053B-4EA4-B503-1DB0CC35FCD5": "ms-Exch-Message-Hygiene-IP-Allow-List-Provider-Config",
	"3CF2E983-E82C-4D10-8D12-FDEFA56C677D": "ms-Exch-Message-Hygiene-IP-Block-List-Config",
	"37865F31-AC7B-4585-A9BE-24DEB5181BE4": "ms-Exch-Message-Hygiene-IP-Block-List-Provider",
	"F4FB3380-04BB-4288-B024-58A12F2A18BB": "ms-Exch-Message-Hygiene-IP-Block-List-Provider-Config",
	"11085AE9-8C93-4BB1-BE06-C1931551D59A": "ms-Exch-Message-Hygiene-Lookup-Domain",
	"E9F01FC0-3499-4110-92C6-0FA6D29B5B74": "ms-Exch-Message-Hygiene-Machine-Generated-Rejection-Response",
	"35813347-3F63-4A40-B2BF-4C3D5C057015": "ms-Exch-Message-Hygiene-Priority",
	"F1CE3119-1866-4A24-8584-9F0F3076094C": "ms-Exch-Message-Hygiene-Provider-Flags",
	"561AE3C6-F135-4151-8AB7-4DA59A9DF4F9": "ms-Exch-Message-Hygiene-Provider-Name",
	"AB765410-A129-48A9-8168-1EBD90A4F21B": "ms-Exch-Message-Hygiene-Quarantine-Mailbox",
	"FE67DAD2-D83B-488A-B320-28A33CE5540E": "ms-Exch-Message-Hygiene-Recipient-Filter-Config",
	"8D21D446-2FDF-418C-B01B-56BD8272E013": "ms-Exch-Message-Hygiene-Rejection-Message",
	"CA790288-AFD8-4A78-B5E3-318660C2A95F": "ms-Exch-Message-Hygiene-Result-Type",
	"7CF54B1D-026D-4E0F-85F0-2666BB908BDD": "ms-Exch-Message-Hygiene-SCL-Delete-Threshold",
	"8F9187EF-5A12-42BF-8DDE-53E37C70A4B2": "ms-Exch-Message-Hygiene-SCL-Junk-Threshold",
	"A03E546F-2C9F-471E-B0A4-09152799597E": "ms-Exch-Message-Hygiene-SCL-Quarantine-Threshold",
	"2D3F7C58-5E87-4D40-A519-958B1EAED8EF": "ms-Exch-Message-Hygiene-SCL-Reject-Threshold",
	"710841FD-DB7B-47B5-89D9-F56E02011CA2": "ms-Exch-Message-Hygiene-Sender-Filter-Config",
	"3019E5C5-2DE3-4236-9EC2-85C2D21AEDA0": "ms-Exch-Message-Hygiene-Sender-ID-Config",
	"37528820-D210-4087-9E14-0ADDB0F9A824": "ms-Exch-Message-Hygiene-Spoofed-Domain-Action",
	"6D7CFF02-C24B-47D0-8CCC-B0BDB9778FFF": "ms-Exch-Message-Hygiene-Static-Entry-Rejection-Response",
	"7C30C74F-B259-4E99-85CA-439F5990ED03": "ms-Exch-Message-Hygiene-Temp-Error-Action",
	"A95FEE9D-B634-41E9-8F8C-D3D9AC1D5941": "ms-Exch-Message-Journal-Recipient",
	"A9647A82-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Message-Track-Log-Filter",
	"31D51DA3-95A9-4A2A-9F81-B2D977F9CA44": "ms-Exch-Metabase-Path",
	"8ADDD6A2-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Mime-Types",
	"8FCA497D-4AC7-4DF4-B180-EEC0BFEF27DF": "ms-Exch-Min-Admin-Version",
	"A9883DC8-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Minimum-Threads",
	"8DDB297C-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Mixed-Mode",
	"C6EB8202-949F-43BD-BA2F-C72F62311CA1": "ms-Exch-MLS-Domain-Gateway-SMTP-Address",
	"3A179935-9064-4071-B8FA-EB5A9245E5D6": "ms-Exch-MLS-Encrypted-Decryption-P12-Current",
	"33E453DF-823D-4EC0-9492-F0F66CA4BBA1": "ms-Exch-MLS-Encrypted-Decryption-P12-Previous",
	"B998E2B5-F30C-45C5-90F7-0D49E4F4EB82": "ms-Exch-MLS-Encrypted-Recovery-P12-Current",
	"5DCB08F1-471A-4811-BBAD-53DC63941D83": "ms-Exch-MLS-Encrypted-Recovery-P12-Previous",
	"557FF252-4D61-4895-89F4-9525F61C27FF": "ms-Exch-MLS-Encrypted-Signing-P12-Current",
	"E2B0E009-D3B9-4EB5-BF74-37786DB2519B": "ms-Exch-MLS-Encrypted-Signing-P12-Previous",
	"E8C82719-0F63-4847-9D00-39436F781585": "ms-Exch-Mobile-Additional-Flags",
	"057CBCAE-359E-46C9-B1B8-38E8C7E37BA7": "ms-Exch-Mobile-Allow-Bluetooth",
	"1B9B1278-2F78-46A4-8A79-1793A16FF9CA": "ms-Exch-Mobile-Allowed-Device-IDs",
	"B50D2F99-4BB1-4EFA-9A34-BAAB877E82FF": "ms-Exch-Mobile-Allow-SMIME-Encryption-Algorithm-Negotiation",
	"A993EF32-E4DF-48C9-9700-13BA274D5F31": "ms-Exch-Mobile-Approved-Application-List",
	"A3431708-B922-45E6-BB4A-05560E5628BB": "ms-Exch-Mobile-Client-Certificate-Authority-URL",
	"1B7AB71F-45A1-4F33-96BF-6258AFAC658D": "ms-Exch-Mobile-Client-Cert-Template-Name",
	"2C2B3787-54C4-4BF0-B25E-EF8FB58BE5D4": "ms-Exch-Mobile-Client-Flags",
	"A8ED9A4A-21FE-452E-BD94-111735073003": "ms-Exch-Mobile-Debug-Logging",
	"F93B950B-101E-4B1F-8555-9C42368837D8": "ms-Exch-Mobile-Default-Email-Truncation-Size",
	"EE331649-C57B-4A5A-A92D-8E85FDF6C6F0": "ms-Exch-Mobile-Device-Number-Of-Previous-Passwords-Disallowed",
	"F6A3EDF2-A222-4C1F-8F7C-DAA2D3B94C3B": "ms-Exch-Mobile-Device-Password-Expiration",
	"9C9D9D13-BB0A-4A14-920D-3AD91855A19A": "ms-Exch-Mobile-Device-Policy-Refresh-Interval",
	"65FA6B59-283D-4E1E-8CCF-2416E33C945B": "ms-Exch-Mobile-Flags",
	"98CFF6A5-30BB-474F-B4D1-DF91AAAAED5E": "ms-Exch-Mobile-Initial-Max-Attachment-Size",
	"5430E777-C3EA-4024-902E-DDE192204669": "ms-Exch-Mobile-Mailbox-Flags",
	"A29670E5-7E7D-4C51-8940-4B4563478746": "ms-Exch-Mobile-Mailbox-Policy",
	"A8EF7ADC-B0A9-42A9-9C7B-E86D8F53FBFC": "ms-Exch-Mobile-Mailbox-Policy-BL",
	"E6B5A02A-F581-4C42-AE60-108FE7C1EDB5": "ms-Exch-Mobile-Mailbox-Policy-Link",
	"D8E754F5-28FD-4899-A706-B9D6115E46D3": "ms-Exch-Mobile-Max-Calendar-Age-Filter",
	"73BD1FFB-FFFE-4186-8FCA-4A0C04FC1422": "ms-Exch-Mobile-Max-Calendar-Days",
	"11BA14E7-27FC-427C-98EE-E31CB30543B6": "ms-Exch-Mobile-Max-Device-Password-Failed-Attempts",
	"7BA83EA5-BCCC-44A0-9F90-72622996CC6C": "ms-Exch-Mobile-Max-Email-Age-Filter",
	"27C6E524-E6BF-41D6-B02C-F8C6A7DE28B1": "ms-Exch-Mobile-Max-Email-Body-Truncation-Size",
	"ADDEF618-51CE-4C7F-A2C6-03A8D3E694AD": "ms-Exch-Mobile-Max-Email-Days",
	"C21AE617-8D74-46DE-AFC3-A7E118134A57": "ms-Exch-Mobile-Max-Email-HTML-Body-Truncation-Size",
	"F8087747-50F7-420E-8344-4AC4B703A564": "ms-Exch-Mobile-Max-Inactivity-Time-Device-Lock",
	"6F675799-74EA-4AEE-A830-AC8B8DEB3DC5": "ms-Exch-Mobile-Min-Device-Password-Complex-Characters",
	"819FDB24-02D8-4AC0-87E4-BB06227490DC": "ms-Exch-Mobile-Min-Device-Password-Length",
	"1CDCE4A0-1AB8-43A7-9D22-C1299E79BC9E": "ms-Exch-Mobile-Outbound-Charset",
	"B2EB0A93-1266-4846-BE62-DFB358681F1B": "ms-Exch-Mobile-Policy-Salt",
	"DE7EFDD4-2137-4234-B802-32958B391E40": "ms-Exch-Mobile-Remote-Documents-Allowed-Servers",
	"5631E540-F332-48D1-9573-8BC2A476F18D": "ms-Exch-Mobile-Remote-Documents-Blocked-Servers",
	"5A979350-0EFC-400F-9222-FC438D177CEC": "ms-Exch-Mobile-Remote-Documents-Internal-Domain-Suffix-List",
	"F32D4B0F-A9B8-4CD8-9A5C-A1A60B6EFFC8": "ms-Exch-Mobile-Require-Encryption-SMIME-Algorithm",
	"39C079C2-D84C-4A39-9FCD-E82AA58E69CB": "ms-Exch-Mobile-Require-Signed-SMIME-Algorithm",
	"1853B86F-BB32-48EB-95A7-4F4633959954": "ms-Exch-Mobile-Unapproved-In-ROM-Application-List",
	"56BA85A5-AD5F-4F8A-B69C-039979AFA366": "ms-Exch-Mobile-Virtual-Directory",
	"0210CC37-34CF-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Monitoring-Disk-Space",
	"E520BE0A-D2EA-449B-9177-CAAADEC1A4C6": "ms-Exch-Monitoring-Mode",
	"0210CC30-34CF-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Monitoring-Monitored-Services",
	"8BF11686-FB18-4147-95E4-F43F8C9DE87D": "ms-Exch-Monitoring-Notification-Rate",
	"A3AF17A5-B2BF-442C-BD04-83DCEDB19EA4": "ms-Exch-Monitoring-Polling-Rate",
	"501B8818-29AE-11D3-AA69-00C04F8EEDD8": "ms-Exch-Monitoring-Queue-Polling-Frequency",
	"501B880F-29AE-11D3-AA69-00C04F8EEDD8": "ms-Exch-Monitoring-Queue-Polling-Interval",
	"C1293AC0-B228-4B41-9409-2CA7D0C19459": "ms-Exch-Monitoring-Resources",
	"0210CC43-34CF-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Monitoring-Responses",
	"03F68F72-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Monitors-Container",
	"AB4CC53C-4BA4-11D3-AA75-00C04F8EEDD8": "ms-Exch-Move-To-LSA",
	"985CFFFA-42FA-4371-AA9F-0214F7B9D2BA": "ms-Exch-MSM-Cert-Policy-Oid",
	"2F2DC2A4-242E-11D3-AA66-00C04F8EEDD8": "ms-Exch-MTA-Database-Path",
	"1529CF7A-2FDB-11D3-AA6D-00C04F8EEDD8": "ms-Exch-Multi-Media-User",
	"EF2C7C70-F874-4280-8643-2334F2D3340C": "ms-Exch-Non-Authoritative-Domains",
	"974C99FE-33FC-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Non-MIME-Character-Set",
	"9FF15C41-1EC9-11D3-AA5E-00C04F8EEDD8": "ms-Exch-No-PF-Connection",
	"04C85E62-A981-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Notes-Connector",
	"AA5A0CB8-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Connector-Mailbox",
	"0C74ACBA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Exclude-Groups",
	"0EB5A5CE-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Export-Groups",
	"137332C0-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Foreign-Domain",
	"141552A8-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Letterhead",
	"13D02E76-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Notes-INI",
	"AA7DCFFE-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Notes-Links",
	"14B51036-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Notes-Server",
	"593FA28D-2862-11D3-AA68-00C04F8EEDD8": "ms-Exch-Notes-Password",
	"90804554-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Routable-Domains",
	"144C28BE-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Rtr-Mailbox",
	"12B6D8FA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Source-Books",
	"13A07F6E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Target-Book",
	"AAD1424C-B093-11D2-AA06-00C04F8EEDD8": "ms-Exch-Notes-Target-Books",
	"14EBE64C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-NT-Account-Options",
	"15278116-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-NT-Authentication-Providers",
	"155BF4D2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Ntds-Export-Containers",
	"1592CAE8-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Ntds-Import-Container",
	"3686CDD4-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-OAB",
	"15C279F0-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-OAB-Default",
	"7D2D4473-36BF-4968-9D72-61CBE31D3354": "ms-Exch-OAB-Flags",
	"15F6EDAC-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-OAB-Folder",
	"5BDB8E44-730A-4FD9-8411-C982384FD4BB": "ms-Exch-OAB-TTL",
	"FD9EBEE2-C759-4940-B21A-5E25E78F1ADC": "ms-Exch-OAB-Virtual-Directories-BL",
	"2DCC7CE7-0EA1-4696-9EA5-BA7CBDA8203E": "ms-Exch-OAB-Virtual-Directories-Link",
	"457E0398-CAFE-43FB-B128-23C9E9F47C20": "ms-Exch-OAB-Virtual-Directory",
	"E60AE80D-7AC9-4E61-9BC3-98CBC0726A99": "ms-Exch-Oma-Admin-Extended-Settings",
	"C1A7BFBE-116B-4737-8CD9-D29EF5B3690E": "ms-Exch-Oma-Admin-Wireless-Enable",
	"8712D34C-27E5-41B2-976E-482AD8C954E7": "ms-Exch-Oma-Carrier",
	"ABE858B8-3DAF-407E-B1A6-3A323ED3334B": "ms-Exch-Oma-Carrier-Address",
	"1FB324AD-2DA3-4548-8F5A-F34457F8AF4A": "ms-Exch-Oma-Carrier-Type",
	"ACA0878D-89F1-45F5-A48F-680B7E550573": "ms-Exch-Oma-Carrier-Url",
	"D7E12BC7-4288-4866-BC91-F0EE18965C15": "ms-Exch-Oma-Configuration",
	"DB0F9ABB-0770-4F09-BA64-7993D91517B7": "ms-Exch-Oma-Configuration-Container",
	"4DC9D0B1-594C-407E-A7D2-426E6C20DABB": "ms-Exch-Oma-Connector",
	"863DAB20-FB40-43A4-A5E1-825B2071050F": "ms-Exch-Oma-Container",
	"DDA38A4D-972A-44A2-9244-0ACB4B1D34D1": "ms-Exch-Oma-Data-Source",
	"A231009F-9DF2-403D-9FBD-99809049722D": "ms-Exch-Oma-Deliverer",
	"CDBF130D-C7E2-4572-94B0-FC9BE7EEF953": "ms-Exch-Oma-Delivery-Provider",
	"1F0E1A69-D62C-4105-991D-ACAFF4B07D71": "ms-Exch-Oma-Delivery-Provider-DN",
	"DF7AF4DF-F318-4E2C-AC43-BE5B4894711C": "ms-Exch-Oma-Device-Capability",
	"0510BDC4-9B19-4D67-93A1-8DDA04C15568": "ms-Exch-Oma-Device-Capability-DN",
	"CA7A8FB3-21D0-4EA7-AF3F-D15C6DF7C094": "ms-Exch-Oma-Device-Type",
	"9EBE537C-F882-473D-980B-CE52202A75D8": "ms-Exch-Oma-Extended-Properties",
	"E827CD6A-B63C-4D44-961A-781A67949A36": "ms-Exch-Oma-Formatter",
	"D0F2588A-701E-4649-9379-062C62B93EF6": "ms-Exch-Oma-Translator",
	"36A0A976-DD8D-4AAD-81FD-A1B5D4016CA8": "ms-Exch-Oma-User",
	"A87D0C40-CBBD-4DA1-BA2E-704832FCA5B1": "ms-Exch-Oma-Validater",
	"366A319C-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Organization-Container",
	"16671DE6-9753-47BF-9A12-BE31ABE0AF08": "ms-Exch-Originating-Forest",
	"F7B66927-7726-4E66-9EA8-EFDF48D65201": "ms-Exch-Orig-MDB",
	"B4C7FE67-B523-4D2E-B56E-AC57B686C7E3": "ms-Exch-Other-Authentication-Flags",
	"9162C4BA-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Overall-Age-Limit",
	"91CE0E8C-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-OVVM-Connector",
	"1BDBF957-6E87-4184-8226-3B5926B167EC": "ms-Exch-OWA-Action-For-Unknown-File-And-MIME-Types",
	"DC1A3AF6-D61B-464D-9B38-F7E4FF3305B5": "ms-Exch-OWA-Allowed-File-Types",
	"A09A785B-A861-41AB-88FA-4B53A5801EAF": "ms-Exch-OWA-Allowed-Mime-Types",
	"9D43751B-71E8-48EE-B888-E430032D1CC3": "ms-Exch-OWA-Blocked-File-Types",
	"FED6213B-BFBF-421A-8A4F-E26DCCD38600": "ms-Exch-OWA-Blocked-MIME-Types",
	"3276FDB9-41E9-4761-9EFA-B56A1A1789DE": "ms-Exch-OWA-Client-Auth-Cleanup-Level",
	"7CC453C5-1A08-40DD-9126-8D3447342112": "ms-Exch-OWA-Default-Client-Language",
	"51D0103D-17C8-44DC-90BA-C6F059AAB955": "ms-Exch-OWA-Default-Theme",
	"C64AD675-772D-4E7D-B695-438E2314C1F0": "ms-Exch-OWA-Exchweb-Proxy-Destination",
	"3141BE44-A4A1-4978-ABF1-7B5405130296": "ms-Exch-OWA-File-Access-Control-On-Private-Computers",
	"DEEA3F96-696C-4EEB-A131-436E2C90A95F": "ms-Exch-OWA-File-Access-Control-On-Public-Computers",
	"0A0AA634-25B0-434C-9F9F-B05DA790C1C2": "ms-Exch-OWA-Filter-Web-Beacons",
	"F04A96C7-6972-4CDA-89E5-64B1492D9726": "ms-Exch-OWA-Force-Save-File-Types",
	"08DF621E-CCF4-4AF1-9A8D-1D84B38B206A": "ms-Exch-OWA-Force-Save-MIME-Types",
	"1CD633B9-8CC9-4E27-A8EE-5FB9EFCAD476": "ms-Exch-OWA-Gzip-Level",
	"30A5AA06-6CA7-43E9-83E3-010DC0E1ED13": "ms-Exch-OWA-Logon-And-Error-Language",
	"A52F8FC3-BC35-459D-9E9D-870913232C8C": "ms-Exch-OWA-Logon-Format",
	"859266C2-BA62-4DDA-825E-A49E7CB04D19": "ms-Exch-OWA-Max-Transcodable-Doc-Size",
	"B379264F-3CF7-4205-B7A7-7F3B8AF11642": "ms-Exch-OWA-Notification-Interval",
	"7B65E689-1D8A-41D0-A5E7-CD32BD8E4244": "ms-Exch-OWA-Outbound-Charset",
	"07B010D7-796F-4762-A634-3CA08161D558": "ms-Exch-OWA-Redirect-To-Optimal-OWA-Server",
	"8AFE48FD-7734-46A1-BD66-647767E430E7": "ms-Exch-OWA-Remote-Documents-Action-For-Unknown-Servers",
	"30EE1024-BF05-4BD3-8560-06CAAFAE0D5E": "ms-Exch-OWA-Remote-Documents-Allowed-Servers",
	"8266E19E-6FF0-4454-938A-DEB0ABC9296C": "ms-Exch-OWA-Remote-Documents-Blocked-Servers",
	"2D67B69D-D74D-4EB7-A064-CD106C1FA0E5": "ms-Exch-OWA-Remote-Documents-Internal-Domain-Suffix-List",
	"7D3AA52C-9668-4CBC-B7EC-B5BF1FA01813": "ms-Exch-OWA-Transcoding-File-Types",
	"CB782856-96CF-4E64-8929-FEB92DC09F33": "ms-Exch-OWA-Transcoding-Flags",
	"A8794E7E-1597-44BF-AA44-6798BE203648": "ms-Exch-OWA-Transcoding-Mime-Types",
	"91558A96-2954-4A75-86AA-360DB3477A49": "ms-Exch-OWA-Use-GB18030",
	"2F745C32-0CAF-4DED-B469-492449037D9C": "ms-Exch-OWA-Use-ISO8859-15",
	"E5A5B2B6-5533-4D81-BBB2-EBE566E4A9BB": "ms-Exch-OWA-User-Context-Timeout",
	"B3B3A864-CD0F-44B9-B0ED-44D0E26351EE": "ms-Exch-OWA-Version",
	"82281FF7-6780-46A6-AE51-17354E8D93FC": "ms-Exch-OWA-Virtual-Directory",
	"00C84968-F248-4AC1-8E20-4C7780AE8EA7": "ms-Exch-OWA-Virtual-Directory-Type",
	"16F86BA4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Owning-Org",
	"172A7D06-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Owning-PF-Tree",
	"175A2C0E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Owning-PF-Tree-BL",
	"17910224-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Owning-Server",
	"8A0C07B2-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Partner-CP",
	"17C7D83A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Partner-Language",
	"BBDF5F8C-02D5-45FF-BAB7-464D5452EBF4": "ms-Exch-Patch-MDB",
	"146C8019-12CA-421E-B89F-243780DA109A": "ms-Exch-Permitted-AuthN",
	"ED1161ED-5D1E-4BB3-993F-11956D680EF6": "ms-Exch-Pf-Creation",
	"3DE926B2-22AF-11D3-AA62-00C04F8EEDD8": "ms-Exch-PF-Default-Admin-ACL",
	"17FEAE50-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-PF-DS-Container",
	"3F50D651-BC97-47B3-AADC-C836D7FEC446": "ms-Exch-Pf-Root-Url",
	"364D9564-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-PF-Tree",
	"1830BFB2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-PF-Tree-Type",
	"C480F22A-BD3F-4797-8DFC-D6A396058182": "ms-Exch-Phonetic-Support",
	"3630F92C-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Policies-Container",
	"61C47258-454E-11D3-AA72-00C04F8EEDD8": "ms-Exch-Policies-Excluded",
	"61C47253-454E-11D3-AA72-00C04F8EEDD8": "ms-Exch-Policies-Included",
	"1865336E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Policy-Default",
	"E32977DC-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Policy-Enabled",
	"92407F6C-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Policy-Last-Applied-Time",
	"18CBB88C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Policy-List",
	"19028EA2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Policy-List-BL",
	"1934A004-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Policy-LockDown",
	"1966B166-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Policy-Option-List",
	"E32977B1-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Policy-Order",
	"E36EF110-1D40-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Policy-Roots",
	"1998C2C8-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Poll-Interval",
	"5AE90713-DA65-4FFD-9D49-BB07C0F91B14": "ms-Exch-Pop-Imap-Banner",
	"97D07C1C-2C62-4E4E-8A13-C91A5B3359A5": "ms-Exch-Pop-Imap-Calendar-Item-Retrieval-Option",
	"E01080D2-4902-40BE-AFDA-89B28E9C54D2": "ms-Exch-Pop-Imap-Command-Size",
	"8E499338-BF64-4414-B70A-A975F6CC602B": "ms-Exch-Pop-Imap-Flags",
	"6DDEE2D2-908E-453B-B28B-5CC39E8F6C9C": "ms-Exch-Pop-Imap-Incoming-Preauth-Connection-Timeout",
	"02E31E1A-C0C9-4699-B8CC-C86BDB879E05": "ms-Exch-Pop-Imap-Max-Incoming-Connection-From-Single-Source",
	"2D77BB78-4820-4235-99F2-369F4269EFDC": "ms-Exch-Pop-Imap-Max-Incoming-Connection-Per-User",
	"2632CD80-7372-490F-BB86-8B12E7FEAAB3": "ms-Exch-Pop-Imap-X509-Certificate-Name",
	"5E03E654-D85D-4908-83A1-6141048C5C62": "ms-Exch-Preferred-Backfill-Source",
	"48464774-30CA-11D3-AA6D-00C04F8EEDD8": "ms-Exch-Prev-Export-DLs",
	"9F7F4160-8942-4E87-A3FD-165B7711E433": "ms-Exch-Previous-Account-Sid",
	"36145CF4-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Private-MDB",
	"35DB2484-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Private-MDB-Policy",
	"B8D47E54-4B78-11D3-AA75-00C04F8EEDD8": "ms-Exch-Private-MDB-Proxy",
	"5AB6A4B0-7D6C-4E84-848E-10D52B1EB735": "ms-Exch-Processed-Sids",
	"1CBF58A0-5E12-4A78-B8EA-42656DF53926": "ms-Exch-Product-ID",
	"F563DF0E-EB5C-48EB-BB2D-4AA0A2C9496A": "ms-Exch-Prompt-Publishing-Point",
	"9432CAE6-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-HTTP-Container",
	"8C7588C0-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-HTTP-Filter",
	"8C58EC88-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-HTTP-Filters",
	"8C3C5050-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-HTTP-Virtual-Directory",
	"9F116EA7-284E-11D3-AA68-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-IM",
	"93DA93E4-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-IMAP-Container",
	"35F7C0BC-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-IMAP-Policy",
	"99F58672-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-IMAP-Sessions",
	"9F116EA3-284E-11D3-AA68-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-IM-Container",
	"9F116EB4-284E-11D3-AA68-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-IM-Virtual-Server",
	"94162EAE-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-NNTP-Container",
	"93F99276-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-POP-Container",
	"35BE884C-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-POP-Policy",
	"99F58676-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-POP-Sessions",
	"90F2B634-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-Protocol-Container",
	"939EF91A-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-Shared-Container",
	"93BB9552-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-SMTP-Container",
	"8B7B31D6-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-SMTP-IP-Address",
	"8B2C843C-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-SMTP-IP-Address-Container",
	"359F89BA-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Protocol-Cfg-SMTP-Policy",
	"47BC3AA6-3634-11D3-AA6E-00C04F8EEDD8": "ms-Exch-Proxy-Custom-Proxy",
	"974C9A02-33FC-11D3-AA6E-00C04F8EEDD8": "msExch-Proxy-Gen-Options",
	"1A2A323A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Proxy-Gen-Server",
	"1A610850-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Proxy-Name",
	"CEC4472B-22AE-11D3-AA62-00C04F8EEDD8": "ms-Exch-Pseudo-PF",
	"9AE2FA1B-22B0-11D3-AA62-00C04F8EEDD8": "ms-Exch-Pseudo-PF-Admin",
	"3582ED82-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Public-Folder-Tree-Container",
	"3568B3A4-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Public-MDB",
	"354C176C-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Public-MDB-Policy",
	"1D86E324-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Purported-Search-UI",
	"399EB12C-E120-473C-B0F7-97AE7CA4988B": "ms-Exch-Query-Base-DN",
	"42730BC3-0A05-4840-8A05-047EF77DABF7": "ms-Exch-Query-Filter",
	"2FE5B0B2-B383-482C-B0EA-900EAF61E9B2": "ms-Exch-Query-Filter-Metadata",
	"8AFA72DA-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Queuing-MDB",
	"95EF4000-D163-46DB-88B8-48EC44E7963C": "ms-Exch-Receive-Hashed-Password",
	"5B1EB3C7-F3BC-4B91-9810-7F1C466886EB": "ms-Exch-Receive-User-Name",
	"B893ABB0-767E-4F20-915F-3857BBC96AFE": "ms-Exch-Recipient-Display-Type",
	"6C97E7D7-6F8B-4DB8-BBB1-3FF9C6494849": "ms-Exch-Recipient-Filter-Flags",
	"E32977D8-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Recipient-Policy",
	"E32977D2-1D31-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Recipient-Policy-Container",
	"05377276-3F2A-4C7A-90D6-10DA53E84A62": "ms-Exch-Recipient-Template",
	"4C6F944B-ED87-40B7-B780-C7298BF1D9C9": "ms-Exch-Recipient-Template-Flags",
	"069BA1F8-540A-42A9-BF26-A7DD35475346": "ms-Exch-Recipient-Type-Details",
	"1DD7F318-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Recip-Limit",
	"2E0A68E1-BDD7-4899-8BB2-D6EA007558C7": "ms-Exch-Recip-Turf-List-Names",
	"870B36B3-D035-402D-B873-CED07B173763": "ms-Exch-Recip-Turf-List-Options",
	"1E007B12-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Recovery",
	"1E29030C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Remote-Private-IS-List",
	"1E58B214-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Remote-Server-List",
	"1EAC2462-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Replicate-Now",
	"99F58682-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Replication-Connector",
	"99F5867E-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Replication-Connector-Container",
	"1ED70EB6-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Replication-Msg-Size",
	"1F01F90A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Replication-Schedule",
	"1F2CE35E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Replication-Style",
	"F533EB3B-F75B-4FB3-B2FB-08CD537A84D1": "ms-Exch-RequireAuthToSendTo",
	"E24D7AA1-439D-11D3-AA72-00C04F8EEDD8": "ms-Exch-Resolve-P2",
	"6BDF2F2A-D81D-4981-9AA7-C98D10D5731A": "ms-Exch-Resource-Address-Lists",
	"8798118C-2436-4762-BE81-892069D725EC": "ms-Exch-Resource-Capacity",
	"4516994B-89E4-4FEC-AC69-8C2953EF4F00": "ms-Exch-Resource-Display",
	"1F57CDB2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Resource-GUID",
	"D6C38FA8-1E9C-402D-B33D-46B49E462071": "ms-Exch-Resource-Location-Schema",
	"8DAF2C70-36C1-4FCD-B664-7335DDC1AA3C": "ms-Exch-Resource-Meta-Data",
	"912BEEA4-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Resource-Properties",
	"746197C7-970E-40D2-B193-32BAA006005D": "ms-Exch-Resource-Property-Schema",
	"AD49D311-957C-43CD-B7CD-D005A868ABEE": "ms-Exch-Resource-Schema",
	"292EE3BD-AB78-460D-9830-7987CCECCC2D": "ms-Exch-Resource-Search-Properties",
	"9FF15C37-1EC9-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Responsible-MTA-Server",
	"9FF15C3C-1EC9-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Responsible-MTA-Server-BL",
	"A1EDCB4C-5C45-4D4A-B128-880392E9DCC6": "ms-Exch-Restore",
	"7FDEB080-2491-484D-96D3-E1A21165BC1D": "ms-Exch-RMS-Template-Path",
	"1F8055AC-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Role-Includes",
	"1FA8DDA6-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Role-Localized-Names",
	"1FD165A0-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Role-Rights",
	"881759DE-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Accept-Message-Type",
	"909A7F32-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Disallow-Priority",
	"88DADAB2-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Display-Sender-Enabled",
	"89F1CDD4-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Enabled",
	"62A383C0-2D9D-11D3-AA6B-00C04F8EEDD8": "ms-Exch-Routing-ETRN-Domains",
	"35154156-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Routing-Group",
	"899E5B86-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Group-Connector",
	"34DE6B40-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Routing-Group-Container",
	"FA9635C0-4ACB-47DE-AD00-1880B590481B": "ms-Exch-Routing-Group-Members-BL",
	"1FF9ED9A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Group-Members-DN",
	"2024D7EE-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Master-DN",
	"88F51490-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Oversized-Schedule",
	"89141322-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Oversized-Style",
	"89BAF7BE-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-SMTP-Connector",
	"892E4D00-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Triggered-Schedule",
	"894AE938-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Routing-Triggered-Style",
	"4ED4E88C-175B-4C5B-AB6D-0E86BC87A24C": "ms-Exch-Rpc-Http-Flags",
	"A5783DA9-38F0-4F51-8ED7-D5BD9BFB0FDE": "ms-Exch-Rpc-Http-Virtual-Directory",
	"6F606079-3A82-4C1B-8EFB-DCC8C91D26FE": "ms-Exch-Safe-Recipients-Hash",
	"7CB4C7D3-8787-42B0-B438-3C5D479AD31E": "ms-Exch-Safe-Senders-Hash",
	"209C0D82-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Sasl-Logon-Domain",
	"D93571B4-C99A-4CFC-AABA-2D809FD68E79": "ms-Exch-SASL-Mechanisms",
	"B1FCE956-1D44-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Sched-Plus-AG-Only",
	"B1FCE950-1D44-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Sched-Plus-Full-Update",
	"B1FCE94C-1D44-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Sched-Plus-Schedist",
	"B1FCE946-1D44-11D3-AA5E-00C04F8EEDD8": "ms-Exch-Schedule-Plus-Connector",
	"348AF8F2-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Schema-Map-Policy",
	"20C6F7D6-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Schema-Policy-Consumers",
	"60735C93-C60E-405E-B5EA-CB31F68AD548": "ms-Exch-Schema-Version-Adc",
	"5F8198D5-E7C9-4560-B166-08DC7CFC17C1": "ms-Exch-Schema-Version-Pt",
	"20FB6B92-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Scope-Mask",
	"1884A3FE-EFCB-47B0-BBD4-A91EF8CD4CB4": "ms-Exch-Search-Base",
	"05ED1E50-31C8-4ED2-B01E-732DBF6DD344": "ms-Exch-Search-Scope",
	"216DDC72-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Secure-Bindings",
	"B8D47E4E-4B78-11D3-AA75-00C04F8EEDD8": "ms-Exch-Security-Password",
	"981A8E4C-CD98-478B-9D01-F776E0DE58C8": "ms-Exch-Send-Encrypted-Password",
	"66A31681-CF58-41A8-A725-8361B9E806BE": "ms-Exch-Sender-Reputation",
	"CE0D9F0C-ACA3-4BC2-88BA-EBB4A3DEF1A9": "ms-Exch-Sender-Reputation-Cisco-Ports",
	"4B642A37-36EF-49E7-ABFB-29EECB9D6888": "ms-Exch-Sender-Reputation-Http-Connect-Ports",
	"B27A8520-D7A4-4D00-AA05-4032E6CBBD7A": "ms-Exch-Sender-Reputation-Http-Post-Ports",
	"E6A94062-2AF9-4C43-866C-CD86F692C7EB": "ms-Exch-Sender-Reputation-Max-Download-Interval",
	"27DD2F0E-AC0A-442F-993A-A647A9F98D67": "ms-Exch-Sender-Reputation-Max-Idle-Time",
	"E822C0BB-1DB3-432A-A1B9-09151FAC77D0": "ms-Exch-Sender-Reputation-Max-Pending-Operations",
	"5986CDF7-8B93-4C8D-BFCA-BBFFE2F9C283": "ms-Exch-Sender-Reputation-Max-Work-Queue-Size",
	"C532822B-8E3A-4AC9-9E78-EE029003F627": "ms-Exch-Sender-Reputation-Min-Download-Interval",
	"317373E0-0F2B-413F-BBD3-818CE50A111F": "ms-Exch-Sender-Reputation-Min-Message-Per-Time-Slice",
	"A44DD6B7-8784-40E9-B229-7018B1A44CD4": "ms-Exch-Sender-Reputation-Min-Messages-Per-Database-Transaction",
	"8B439B94-98B7-418F-8E21-30B0F702EC0E": "ms-Exch-Sender-Reputation-Min-Reverse-Dns-Query-Period",
	"6345A722-83FA-41FE-94A1-8ECE707F59E6": "ms-Exch-Sender-Reputation-Open-Proxy-Flags",
	"95BBD180-C5B0-4DCC-B443-2D8307DDD199": "ms-Exch-Sender-Reputation-Open-Proxy-Rescan-Interval",
	"7F804A06-674B-4951-B0BA-3BF8DF129CBB": "ms-Exch-Sender-Reputation-Proxy-Server-IP",
	"01FAB06C-C8FE-4E8D-A53B-5E46236F77B3": "ms-Exch-Sender-Reputation-Proxy-Server-Port",
	"81CF7ADD-09D4-4683-A25B-6D29AA66EADC": "ms-Exch-Sender-Reputation-Proxy-Server-Type",
	"9D2AF688-C79E-4637-9CFE-E2F740A148B3": "ms-Exch-Sender-Reputation-Sender-Blocking-Period",
	"84B294CD-1782-4061-8D63-F04F2D163991": "ms-Exch-Sender-Reputation-Service-Url",
	"321358A4-70B1-4269-8336-F6AC6F6FDC5A": "ms-Exch-Sender-Reputation-Socks4-Ports",
	"58635C3F-B2E8-494F-A996-4E0FD303C14E": "ms-Exch-Sender-Reputation-Socks5-Ports",
	"A2875B38-1404-4CBB-BE50-022FE213BE16": "ms-Exch-Sender-Reputation-Srl-Block-Threshold",
	"0071CAD5-A0A3-4C7C-8330-367E1C5E68A1": "ms-Exch-Sender-Reputation-Srl-Settings-Database-File-Name",
	"E7A33E12-80C7-4FEE-9A4C-35878A66B3D6": "ms-Exch-Sender-Reputation-Table-Purge-Interval",
	"C9F1922C-2FB6-4B11-ADD2-2F1A338DA9E2": "ms-Exch-Sender-Reputation-Telnet-Ports",
	"1F2A73D0-CE75-4FD7-8F7E-6DA61F5AFC7E": "ms-Exch-Sender-Reputation-Time-Slice-Interval",
	"1F3B047F-6330-4ACE-8552-FF1DF5C47077": "ms-Exch-Sender-Reputation-Wingate-Ports",
	"43C52481-084B-4546-A896-69C94199ABD5": "ms-Exch-Send-User-Name",
	"222EFAEC-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Always-Create-As",
	"225EA9F4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Authentication-Credentials",
	"228BF6A2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Authentication-Password",
	"22B94350-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Authentication-Type",
	"22EDB70C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Deletion-Option",
	"231B03BA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Export-Containers",
	"234D151C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Flags",
	"237F267E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Highest-USN",
	"7FB58CD4-2A6E-11D3-AA6B-00C04F8EEDD8": "ms-Exch-Server1-Highest-USN-Vector",
	"23AED586-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Import-Container",
	"90B71B6A-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Is-Bridgehead",
	"23E34942-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Last-Update-Time",
	"2412F84A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Network-Address",
	"2449CE60-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-NT-Account-Domain",
	"247BDFC2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Object-Match",
	"24B0537E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Page-Size",
	"24E264E0-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Port",
	"25193AF6-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Schema-Map",
	"254DAEB2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Search-Filter",
	"258484C8-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-SSL-Port",
	"25BB5ADE-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server1-Type",
	"25F95802-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Always-Create-As",
	"26329072-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Authentication-Credentials",
	"266BC8E2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Authentication-Password",
	"26A50152-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Authentication-Type",
	"26E09C1C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Deletion-Option",
	"27CCA4EA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Export-Containers",
	"28083FB4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Flags",
	"283A5116-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Highest-USN",
	"7FB58CDA-2A6E-11D3-AA6B-00C04F8EEDD8": "ms-Exch-Server2-Highest-USN-Vector",
	"286C6278-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Import-Container",
	"90D619FC-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Is-Bridgehead",
	"28A3388E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Last-Update-Time",
	"28D549F0-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Network-Address",
	"2909BDAC-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-NT-Account-Domain",
	"293E3168-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Object-Match",
	"296DE070-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Page-Size",
	"29A4B686-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Port",
	"29D6C7E8-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Schema-Map",
	"2A0B3BA4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Search-Filter",
	"2A3FAF60-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-SSL-Port",
	"2A74231C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server2-Type",
	"23D29F88-7FEB-4A18-B11E-7C226FF04AD6": "ms-Exch-Server-Admin-Delegation-BL",
	"CCA785F2-A896-4AED-B26A-8892DE4B7A3C": "ms-Exch-Server-Admin-Delegation-Link",
	"21CF9CDC-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server-Auto-Start",
	"2201AE3E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server-Bindings",
	"61AEDFFA-34B4-4170-8BAB-B8794E1CB4F4": "ms-Exch-Server-Bindings-Filtering",
	"0B836D98-3B20-11D3-AA6F-00C04F8EEDD8": "ms-Exch-Server-Bindings-Turflist",
	"5EC119E9-9690-44E7-AFBD-057E2B0C0F84": "ms-Exch-Server-EKPK-Public-Key",
	"9A3ADFCE-B077-4A97-8A7F-8CD2A4D0CDF6": "ms-Exch-Server-Encrypted-KPK",
	"419F00F6-FB22-4EA9-8113-ED928767BAA5": "ms-Exch-Server-Global-Groups",
	"5FD75FB9-3819-4D25-B18E-7BCE391D4767": "ms-Exch-Server-Groups",
	"D0AD315B-0A1D-42E3-B93C-47B119C2D59A": "ms-Exch-Server-Internal-TLS-Cert",
	"924A0B14-EA4F-4627-ABD1-ADBC801C4B0B": "ms-Exch-Server-Local-Groups",
	"B83DF2DF-C304-4563-90FD-D38EC81B04CB": "ms-Exch-Server-Public-Key",
	"8945707B-7938-48FC-9B23-8AF91D47A193": "ms-Exch-Server-Redundant-Machines",
	"8C8FC29E-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Server-Role",
	"346E5CBA-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Servers-Container",
	"85CA67B3-A515-41BF-B78F-C32A69A000F6": "ms-Exch-Server-Site",
	"99F5867B-12E8-11D3-AA58-00C04F8EEDD8": "ms-Exch-Site-Replication-Service",
	"2AAAF932-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-SLV-File",
	"2B164304-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Authorized-TRN-Accounts",
	"2B5904DC-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Bad-Mail-Directory",
	"86C24F8C-259B-4F19-88B9-9C9445936121": "ms-Exch-Smtp-Connection-Rules-Priority",
	"7EEA7DE9-319E-408A-8460-E35E2C9DA389": "ms-Exch-Smtp-Connection-Turf-List",
	"73FB04AC-B2D4-4A4D-8520-757DD3C9261A": "ms-Exch-Smtp-Connection-Turf-List-Display",
	"3FEE7DE6-D3E5-43CB-8459-F7A072AE3789": "ms-Exch-Smtp-Connection-Turf-List-DNS",
	"BC0241AF-9D38-4C40-842E-51D802506DE5": "ms-Exch-Smtp-Connection-Turf-List-Mask",
	"5AE62360-1105-4D8B-8A1E-A2C793B4D57D": "ms-Exch-Smtp-Connection-Turf-List-Options",
	"EEDDD98F-DA01-4ECB-A65E-5F016F1D8032": "ms-Exch-Smtp-Connection-Turf-List-Response",
	"6ABADFAD-E2F6-4DDB-9820-0DA9C47DA32C": "ms-Exch-Smtp-Connection-Turf-List-Rule",
	"87CF463A-561E-45CE-A0BA-6D528F111D23": "ms-Exch-Smtp-Connection-Whitelist",
	"2BD03A70-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Domain-String",
	"2B949FA6-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Do-Masquerade",
	"2C260F18-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Drop-Directory",
	"2C6D95A4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ds-Data-Directory",
	"2CADF522-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ds-Default-Mail-Root",
	"2CE72D92-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ds-Domain",
	"2D206602-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ds-Flags",
	"2D599E72-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ds-Host",
	"2D92D6E2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ds-Port",
	"E24D7A86-439D-11D3-AA72-00C04F8EEDD8": "ms-Exch-Smtp-Enable-EXPN",
	"2DCE71AC-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Enable-Ldap-Routing",
	"E24D7A80-439D-11D3-AA72-00C04F8EEDD8": "ms-Exch-Smtp-Enable-VRFY",
	"A1826432-F85E-42B6-B55D-1249ED2F78A3": "ms-Exch-Smtp-External-DNS-Servers",
	"2E0547C2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Fully-Qualified-Domain-Name",
	"752CD028-A935-40AA-8F8B-14AEB4433C93": "ms-Exch-SMTP-Global-IP-Accept-List",
	"61E731DC-484D-4566-8AAC-C54747F13CC4": "ms-Exch-SMTP-Global-IP-Deny-List",
	"2E40E28C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Inbound-Command-Support-Options",
	"2E7C7D56-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ldap-Account",
	"2EBCDCD4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ldap-Bind-Type",
	"2EF61544-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ldap-Naming-Context",
	"2F2F4DB4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ldap-Password",
	"2F688624-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Ldap-Schema-Type",
	"2F9F5C3A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Local-Queue-Delay-Notification",
	"40BD7E66-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Local-Queue-Expiration-Timeout",
	"40EACB14-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Masquerade-Domain",
	"411817C2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Hop-Count",
	"4147C6CA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Message-Size",
	"417775D2-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Outbound-Msg-Per-Domain",
	"41A724DA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Outbound-Msg-Per-Domain-Flag",
	"41D9363C-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Outgoing-Connections",
	"420B479E-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Outgoing-Connections-Per-Domain",
	"423AF6A6-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Recipients",
	"426AA5AE-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Max-Session-Size",
	"429CB710-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Outbound-Security-Flag",
	"42EDC704-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Outbound-Security-Password",
	"43249D1A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Outbound-Security-User-Name",
	"436037E4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Outgoing-Connection-Timeout",
	"43B3AA32-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Outgoing-Port",
	"43F1A756-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Outgoing-Secure-Port",
	"441EF404-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Perform-Reverse-Dns-Lookup",
	"444054F0-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Pickup-Directory",
	"4468DCEA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Queue-Directory",
	"E9F81BB3-3593-438E-8A4F-ED2842ADFF97": "ms-Exch-Smtp-Receive-Advertised-Domain",
	"5367B285-3AC0-46AC-A945-0AC1FA9C28A7": "ms-Exch-Smtp-Receive-Banner",
	"6408DC1D-D8A3-4168-AA75-816F3E9AC211": "ms-Exch-Smtp-Receive-Bindings",
	"EAD1293A-CC71-450B-A882-436C8DBD8F24": "ms-Exch-Smtp-Receive-Connection-Inactivity-Timeout",
	"65BD296D-50BD-41C8-98C8-84EE6DFC1A48": "ms-Exch-Smtp-Receive-Connection-Timeout",
	"44601346-776A-46E7-B4A4-2472E1C66806": "ms-Exch-Smtp-Receive-Connector",
	"88B5E259-A18F-4202-ADC3-CD24A603B266": "ms-Exch-SMTP-Receive-Connector-FQDN",
	"21009FBE-E727-4E41-8952-C9C80F3DD3AB": "ms-Exch-SMTP-Receive-Default-Accepted-Domain-Link",
	"F6BF6370-69B6-4707-A1DB-5AA160319AC9": "ms-Exch-Smtp-Receive-Enabled",
	"E995A875-A338-4861-81EE-A55D80D965DA": "ms-Exch-SMTP-Receive-Externally-Secured-As",
	"37948E6B-57DE-4ECD-A84A-E95795340505": "ms-Exch-SMTP-Receive-Inbound-Security-Flag",
	"76A2A0FD-3107-422E-A3D2-D7B503BCB5F6": "ms-Exch-Smtp-Receive-Max-Connection-Rate-Per-Minute",
	"CCC12D3D-2C0A-4300-BEB1-7EC35EF1B556": "ms-Exch-Smtp-Receive-Max-Header-Size",
	"6DBB15A2-F2AC-4BDC-A5DE-85BE91C77AA5": "ms-Exch-Smtp-Receive-Max-Hop-Count",
	"7D517B36-EDFF-48C6-A5B2-295C8EFDA784": "ms-Exch-Smtp-Receive-Max-Inbound-Connections",
	"6BFA4308-289B-4433-8E91-540567C30C9A": "ms-Exch-SMTP-Receive-Max-Inbound-Connections-Perc-Per-Source",
	"683D2C5D-C46B-49A8-93EE-ACC5F01AF525": "ms-Exch-Smtp-Receive-Max-Inbound-Connections-Per-Source",
	"30C6A8BE-BBC7-4EE7-840D-E931284519F9": "ms-Exch-Smtp-Receive-Max-Local-Hop-Count",
	"5DE583FF-76B0-4D32-B564-16883ABCFF87": "ms-Exch-Smtp-Receive-Max-Logon-Failures",
	"BF89C828-3865-4DB2-8436-CF256EBD2B6A": "ms-Exch-Smtp-Receive-Max-Message-Size",
	"5606A655-9F98-47D4-99AC-E4249239D5B4": "ms-Exch-Smtp-Receive-Max-Messages-Per-Connection",
	"4117E174-61A4-42EB-A919-363A4C543B28": "ms-Exch-Smtp-Receive-Max-Protocol-Errors",
	"2030B854-AF1B-494E-9DC3-100D7FADE7B4": "ms-Exch-Smtp-Receive-Max-Recipients-Per-Message",
	"43B1FED4-51CC-45E0-B352-8FCACD3A3FA7": "ms-Exch-SMTP-Receive-Postmaster-Address",
	"14A01DC7-E3DB-403A-92A5-66B72D8C12AC": "ms-Exch-Smtp-Receive-Protocol-Logging-Level",
	"75F8E34D-C41A-4D09-A829-38061D0B18C0": "ms-Exch-Smtp-Receive-Protocol-Options",
	"C4520DCC-C68F-4FE4-85D8-95D25CC6CC4A": "ms-Exch-Smtp-Receive-Protocol-Restrictions",
	"8AA13828-0E1C-49BF-97B3-09670B95F717": "ms-Exch-SMTP-Receive-Relay-Control",
	"1E654383-9804-4741-A7DE-75F30B63FF0F": "ms-Exch-Smtp-Receive-Remote-IP-Ranges",
	"176A249B-69CE-4A5F-8FC8-4D49448EA305": "ms-Exch-Smtp-Receive-Security-Descriptor",
	"54BD6B59-8555-4725-AE87-DA04F183C6A1": "ms-Exch-Smtp-Receive-Tarpit-Interval",
	"8560430C-AEC4-4624-A5B2-6357FE90D358": "ms-Exch-Smtp-Receive-Tls-Certificate-Name",
	"7ED2782B-1B8A-4764-BDCF-44C06A4F1033": "ms-Exch-Smtp-Receive-Type",
	"449164E4-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Relay-For-Auth",
	"44B5282A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Relay-Ip-List",
	"44DDB024-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Remote-Queue-Delay-Notification",
	"4501736A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Remote-Queue-Expiration-Timeout",
	"4527990A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Remote-Queue-Retries",
	"454DBEAA-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Routing-Table-Type",
	"E5CC073B-1FFB-4752-AB71-0B592D6B5086": "ms-Exch-Smtp-Send-Advertised-Domain",
	"4586F71A-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Send-Badmail-To",
	"F93B462B-DF8C-4FE5-B5A1-B268CE3AF5BE": "ms-Exch-Smtp-Send-Binding-IP-Address",
	"98F9A09D-8331-48CF-86C2-817CB0F1322A": "ms-Exch-Smtp-Send-Connection-Timeout",
	"20309CBD-0AE3-4876-9114-5738C65F845C": "ms-Exch-SMTP-Send-Connector-FQDN",
	"70CF2B9D-A9FA-42AC-9AE2-D04F3C95D00E": "ms-Exch-Smtp-Send-Enabled",
	"48CC9078-DA0E-405D-ABBA-1893B4C6DDF8": "ms-Exch-SMTP-Send-Externally-Secured-As",
	"EA56B1E8-9BFD-49D4-B37D-28A9F441B102": "ms-Exch-Smtp-Send-Flags",
	"45BB6AD6-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Send-NDR-To",
	"99924333-5DC4-4654-84C1-F9B4344FA97D": "ms-Exch-Smtp-Send-Port",
	"CE2E338A-9877-4B1D-92B0-6F9FB4934CBF": "ms-Exch-Smtp-Send-Protocol-Logging-Level",
	"C2B70009-7171-4404-B064-AC67B1DB5BF0": "ms-Exch-Smtp-Send-Receive-Connector-Link",
	"74650E0F-0919-4B24-8E71-34B700AA9FE3": "ms-Exch-Smtp-Send-Type",
	"45E19076-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Smart-Host",
	"46008F08-B098-11D2-AA06-00C04F8EEDD8": "ms-Exch-Smtp-Smart-Host-Type",
	"BE41789C-2DA8-11D3-AA6B-00C04F8EEDD8": "ms-Exch-Smtp-TRN-Smart-Host",
	"0B836DA5-3B20-11D3-AA6F-00C04F8EEDD8": "ms-Exch-SMTP-Turf-List",
	"91B17254-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-SNADS-Connector",
	"203D2F32-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Source-BH-Address",
	"206F4094-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Source-Bridgehead-Servers-DN",
	"73642506-0282-43EB-A9BD-9DCB129C015D": "ms-Exch-Standby-Copy-Machines",
	"3435244A-A982-11D2-A9FF-00C04F8EEDD8": "ms-Exch-Storage-Group",
	"E2CEFBCC-DCC1-45A5-BAB8-D5F4BD78884D": "ms-Exch-SubmitRelaySD",
	"20A151F6-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Synchronization-Direction",
	"9CF1AA93-B31C-4725-9D50-AB7AB1D3CA1E": "ms-Exch-System-Mailbox",
	"0BFFA04C-7D8E-44CD-968A-B2CAC11D17E1": "ms-Exch-System-Objects-Container",
	"BA085A33-8807-4C6C-9522-2CF5A2A5E9C2": "ms-Exch-System-Policy",
	"32412A7A-22AF-479C-A444-624C0137122E": "ms-Exch-System-Policy-Container",
	"20DA8A66-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Target-Bridgehead-Servers-DN",
	"211FAE98-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Template-RDNs",
	"872A2C26-E51F-4E17-AC2E-AF91C0247E08": "ms-Exch-Tls-Alternate-Subject",
	"63AAFA32-0469-4780-8124-0B6F6E6504E5": "ms-Exch-TLS-Receive-Domain-Secure-List",
	"3284B770-0959-4373-9529-C57C071F2986": "ms-Exch-TLS-Send-Domain-Secure-List",
	"2196E42C-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Track-Duplicates",
	"6BB358B3-96C3-4D49-A527-5A2DAFB7D29F": "ms-Exch-Transport-Connectivity-Log-Directory-Size",
	"F28849F1-B727-4875-9631-A4D77A71AC8E": "ms-Exch-Transport-Connectivity-Log-File-Size",
	"2C8BE23B-891C-4D6A-95C4-AAACCF3718AB": "ms-Exch-Transport-Connectivity-Log-Path",
	"82906765-40E3-4720-B6B4-C4EDD2C884BB": "ms-Exch-Transport-Delay-Notification-Timeout",
	"084E4326-A763-4924-B195-23266387881E": "ms-Exch-Transport-Drop-Directory-Name",
	"15E02A32-1B7D-4112-8B3B-6FE3EC8050A7": "ms-Exch-Transport-Drop-Directory-Quota",
	"D24029FA-C2A4-4096-923C-AA3EDA67997C": "ms-Exch-Transport-External-Default-Language",
	"EA8711D6-CD4E-4393-872E-CD51B94E4F61": "ms-Exch-Transport-External-DNS-Adapter-Guid",
	"9C29A174-2EA1-45AB-A4EE-053C0ED6CF2C": "ms-Exch-Transport-External-DNS-Protocol-Option",
	"EFA0FC2F-D57C-46CA-BA9D-075DE4D18C8B": "ms-Exch-Transport-External-DSN-Reporting-Authority",
	"1F540F8B-1556-4234-A7F1-9A7FBCD58F53": "ms-Exch-Transport-External-IP-Address",
	"77D38312-37BF-4A45-AEFB-7BB420E9BBDB": "ms-Exch-Transport-External-Max-DSN-Message-Attachment-Size",
	"96C984D5-35A1-4FCB-AF00-DF0FA34563A0": "ms-Exch-Transport-External-Postmaster-Address",
	"052ED1E9-C417-4503-A805-327B48DAA4CA": "ms-Exch-Transport-External-Trusted-Servers",
	"DA21AC8D-71CA-4781-93C4-1BA2E0696ABE": "ms-Exch-Transport-Flags",
	"73B7AA28-C725-4A63-9F07-360E67797BCC": "ms-Exch-Transport-Internal-Default-Language",
	"580A335C-F4A4-48C7-8428-45983F925810": "ms-Exch-Transport-Internal-DNS-Adapter-Guid",
	"E311EAEA-DC16-410B-9F4E-74DE2C64FCD2": "ms-Exch-Transport-Internal-DNS-Protocol-Option",
	"BBCBA5AC-98F4-4DB2-B00D-5F4634673DD1": "ms-Exch-Transport-Internal-DNS-Servers",
	"2597B9D5-553D-4A08-B9AD-1B7A06AB4496": "ms-Exch-Transport-Internal-DSN-Reporting-Authority",
	"661C7A76-2C6F-49CA-9839-F170CF000D52": "ms-Exch-Transport-Internal-Max-DSN-Message-Attachment-Size",
	"2401FE52-C440-4106-88E0-C738112EE6E1": "ms-Exch-Transport-Internal-Postmaster-Address",
	"C52F01FD-2C29-4DBA-8266-1A5B24354958": "ms-Exch-Transport-Max-Concurrent-Mailbox-Deliveries",
	"CD55CB2C-9BB4-4E7B-BCCD-3125E5880A27": "ms-Exch-Transport-Max-Concurrent-Mailbox-Submissions",
	"90E8E933-A32A-495E-A1FC-E272F1D59EFF": "ms-Exch-Transport-Max-Connectivity-Log-Age",
	"237DB0AA-E613-45D0-B9CB-1D48D756F973": "ms-Exch-Transport-Max-Message-Tracking-Directory-Size",
	"3BDBC26D-4F49-4103-B554-683EBA655F16": "ms-Exch-Transport-Max-Message-Tracking-File-Size",
	"BBC58701-4E17-491D-B4BC-F82E54E97C11": "ms-Exch-Transport-Max-Message-Tracking-Log-Age",
	"415956F5-86F9-45ED-BCE8-C7F3B209A434": "ms-Exch-Transport-Max-Pickup-Directory-Header-Size",
	"0137DCEC-DBE4-4F92-ACED-594BAACA0CAD": "ms-Exch-Transport-Max-Pickup-Directory-Message-Size",
	"AC791A68-0DED-4FBA-B53F-2CC9F49C3439": "ms-Exch-Transport-Max-Pickup-Directory-Messages-Per-Minute",
	"CFF6AB55-E291-4F2F-9C01-E0224BD27C89": "ms-Exch-Transport-Max-Pickup-Directory-Recipients",
	"9D4BC004-9626-4E5C-8065-2BDC5E9DD70D": "ms-Exch-Transport-Max-Queue-Idle-Time",
	"672E6C8B-C8A6-446F-9667-0434C1364268": "ms-Exch-Transport-Max-Receive-Protocol-Log-Age",
	"2EDC6DE8-17D4-4503-9541-59ECFD6591FF": "ms-Exch-Transport-Max-Receive-Protocol-Log-Directory-Size",
	"285AC9BE-D698-4F63-B55D-23E1C103CC4D": "ms-Exch-Transport-Max-Receive-Protocol-Log-File-Size",
	"D9DF725C-59DD-483B-BB9B-136B0B06D79E": "ms-Exch-Transport-Max-Send-Protocol-Log-Age",
	"BFC689F2-6CF3-4A2C-805A-CED61F5AD4C0": "ms-Exch-Transport-Max-Send-Protocol-Log-Directory-Size",
	"3526AF44-F92C-4FBF-A156-9174B19E29EB": "ms-Exch-Transport-Max-Send-Protocol-Log-File-Size",
	"3F370881-7631-463F-A9EC-5EF2419A99A7": "ms-Exch-Transport-Message-Expiration-Timeout",
	"E088074E-94EB-4F56-A290-BA7904CB0FF3": "ms-Exch-Transport-Message-Retry-Interval",
	"85E6CB8C-7650-46B6-BE40-0212F3908684": "ms-Exch-Transport-Message-Tracking-Path",
	"9F9307E1-61A6-44FE-82FD-317D7AB5A4CB": "ms-Exch-Transport-Outbound-Connection-Failure-Retry-Interval",
	"D275E368-C7D7-48C6-BE74-0D368E6EF376": "ms-Exch-Transport-Outbound-Protocol-Logging-Level",
	"0212ED3A-B0C9-47B8-B49F-6DFFCD673504": "ms-Exch-Transport-Per-Queue-Message-Dehydration-Threshold",
	"33E5848B-7424-4170-9E8C-C90CE0D4A765": "ms-Exch-Transport-Pickup-Directory-Path",
	"681E59F0-DA7E-4CE7-B790-8C380AD0FC1A": "ms-Exch-Transport-Pipeline-Tracing-Path",
	"857CF6EB-BE54-47F0-B553-BD8163503317": "ms-Exch-Transport-Pipeline-Tracing-Sender-Address",
	"1883A897-0DE5-4FE1-95F2-570C74C04642": "ms-Exch-Transport-Poison-Message-Threshold",
	"671678DE-D55D-4B6E-B3FF-900A6301CF02": "ms-Exch-Transport-Receive-Protocol-Log-Path",
	"181757C7-E7AA-44F4-9698-2EF5DB09797C": "ms-Exch-Transport-Replay-Directory-Path",
	"5EAD7D97-6156-4649-B6CA-FA650E30323F": "ms-Exch-Transport-Root-Drop-Directory-Path",
	"52258C5C-49AA-4D3A-A3F5-E7343C0411C6": "ms-Exch-Transport-Routing-Log-Max-Age",
	"CA6B2C83-EB6C-4164-A5C4-54EBFE34417F": "ms-Exch-Transport-Routing-Log-Max-Directory-Size",
	"1E94D6DB-CC7B-42CB-A51D-145F1A8E0EAE": "ms-Exch-Transport-Routing-Log-Path",
	"FB031BAE-BAAC-4599-8E29-2710DF94FA0C": "ms-Exch-Transport-Rule",
	"2230472B-4DC2-46AF-9EB9-48F85E86471B": "ms-Exch-Transport-Rule-Collection",
	"FB7C3663-BC2C-4BF7-820E-03D6D481E95D": "ms-Exch-Transport-Rule-Priority",
	"FA601087-D9BD-4F29-BE0F-ADEDF92D43E7": "ms-Exch-Transport-Rule-Xml",
	"65AFDD90-33AD-4F6F-9F17-29B998C38957": "ms-Exch-Transport-Security-Descriptor",
	"3EC000D9-6B24-4445-A311-313635DE352C": "ms-Exch-Transport-Send-Protocol-Log-Path",
	"7DC6B928-C5E8-438A-88B5-5E61551297B0": "ms-Exch-Transport-Settings",
	"3BA5DFA9-F7B8-499F-A542-4758F82BA14C": "ms-Exch-Transport-Settings-Flags",
	"9D87B436-F668-4887-97A6-792AA77D87BE": "ms-Exch-Transport-Site-Flags",
	"68A1FA12-91FC-4EA7-954D-BDFA3FDEABCB": "ms-Exch-Transport-Submission-Server-Override-List",
	"20C11750-D1F0-4240-B832-50726B6F351C": "ms-Exch-Transport-Total-Queue-Message-Dehydration-Threshold",
	"41A4579E-4DB4-43A3-9319-4B537B4E30F3": "ms-Exch-Transport-Transient-Failure-Retry-Count",
	"DD308D84-D88F-4005-81E0-E89C9B9778A2": "ms-Exch-Transport-Transient-Failure-Retry-Interval",
	"21D27EF6-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Trk-Log-Cleaning-Interval",
	"567D521F-2F6A-11D3-AA6C-00C04F8EEDD8": "ms-Exch-TUI-Password",
	"567D522A-2F6A-11D3-AA6C-00C04F8EEDD8": "ms-Exch-TUI-Speed",
	"567D5225-2F6A-11D3-AA6C-00C04F8EEDD8": "ms-Exch-TUI-Volume",
	"8B60F7F8-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Turf-List",
	"0B836DAA-3B20-11D3-AA6F-00C04F8EEDD8": "ms-Exch-Turf-List-Action",
	"0B836DA0-3B20-11D3-AA6F-00C04F8EEDD8": "ms-Exch-Turf-List-Names",
	"01DBE64C-BFEB-47CD-9939-8911946BDD6D": "ms-Exch-Turf-List-Options",
	"C5CCDCE1-B399-405F-8AB7-BC6434D2E422": "ms-Exch-Uce",
	"9F297C14-D715-4631-A259-BF51DC52EAC1": "ms-Exch-Uce-Block-Threshold",
	"15E2DB2E-7206-4109-9B94-830F4DEF1B05": "ms-Exch-Uce-Enabled",
	"44CCBD60-6EDE-46F0-8F13-931A9BB5B8E8": "ms-Exch-Uce-Store-Action-Threshold",
	"C7ED0E7C-1CAA-42AA-9FA3-9C7986D472E3": "ms-Exch-UM-Allowed-In-Country-Groups",
	"BFE9DE74-78AA-4828-9507-2D5395F2FA58": "ms-Exch-UM-Allowed-International-Groups",
	"39872559-7B5E-425F-8623-95E14CC4FB15": "ms-Exch-UM-ASR-Enabled",
	"E9FC3238-446F-4558-B74F-6261C7D44567": "ms-Exch-UM-Audio-Codec",
	"A0849BF5-7741-4422-A22D-AE8B08E156DF": "ms-Exch-UM-Auto-Attendant",
	"0D9D9DA7-3864-4149-B958-798ABD1D952F": "ms-Exch-UM-Auto-Attendant-After-Hour-Features",
	"2C89524D-373C-41AA-A764-FC29FFB08FFC": "ms-Exch-UM-Auto-Attendant-Business-Hour-Features",
	"65A0C330-8BEB-4817-B425-46D3C3C278B9": "ms-Exch-UM-Auto-Attendant-Business-Hour-Schedule",
	"8C7AC62E-E9CC-4D34-B20E-C5890A52D616": "ms-Exch-UM-Auto-Attendant-Dialed-Numbers",
	"E53BA257-1D00-4265-9F21-9DC2CB30FEB2": "ms-Exch-UM-Auto-Attendant-Dial-Plan-BL",
	"1E407DCD-7554-4ACC-9AD7-DB001DC99542": "ms-Exch-UM-Auto-Attendant-Dial-Plan-Link",
	"A33AE847-BE13-43C9-AB96-036423EEEB0E": "ms-Exch-UM-Auto-Attendant-Flags",
	"EBC6522F-5AFE-4D6B-A43C-B35D5CF4218E": "ms-Exch-UM-Auto-Attendant-Holiday-Schedule",
	"29B0F6F8-D62B-4B5F-B688-E71AB2CA9A87": "ms-Exch-UM-Auto-Attendant-Time-Zone",
	"D80A776C-A126-4631-8C80-B44F4C2C886E": "ms-Exch-UM-Available-In-Country-Groups",
	"76A0AFA7-7081-4852-A000-F39E73F2A73D": "ms-Exch-UM-Available-International-Groups",
	"04000BD4-0A40-497C-A062-FEDAAA2833AE": "ms-Exch-UM-Available-Languages",
	"D3B17B08-0454-47DF-BF88-73DFE8B7F8F8": "ms-Exch-UM-Available-TTS-Languages",
	"25ECFBC0-3DD2-4C6A-80FA-3E48378B9557": "ms-Exch-UM-Call-Failures-To-Disconnect",
	"D3EFED30-67D2-4719-B9CD-3CB3C95A9663": "ms-Exch-UM-Call-Someone-Enabled",
	"4AB4A2DC-6CC5-4879-BC8B-1E8CD082472D": "ms-Exch-UM-Call-Someone-Scope",
	"53F7C905-E94E-4983-95A2-16EC92218DA5": "ms-Exch-UM-Country-Code",
	"27966DA7-4ECA-464D-B8FF-803035AA20DE": "ms-Exch-UM-Default-Language",
	"C02B3C2A-F405-413B-9D9B-888F0BF55AF1": "ms-Exch-UM-Default-TTS-Language",
	"D5CC2EEE-3216-47E3-A68C-DCB89941D210": "ms-Exch-UM-Dial-By-Name-Primary",
	"A58EF719-194E-4AA6-8DC5-7241DE1534B7": "ms-Exch-UM-Dial-By-Name-Secondary",
	"DF0FD94F-126F-42BD-A02F-AA0BAC5A31D7": "ms-Exch-UM-Dial-Plan",
	"1ABC4444-148F-4A56-AAC9-15EDE8EC2371": "ms-Exch-UM-Dial-Plan-Default-Auto-Attendant-BL",
	"9866D5BA-7BD9-459F-9FB4-6B222101559B": "ms-Exch-UM-Dial-Plan-Default-Auto-Attendant-Link",
	"4D7863E2-0225-43F4-94D7-38AE544D1986": "ms-Exch-UM-Dial-Plan-Flags",
	"1FA2724E-C041-465C-9B28-437592F46D2E": "ms-Exch-UM-Dial-Plan-Subscribers-Allowed",
	"24359755-64C6-4CB2-8A66-3B0EA6B2D14A": "ms-Exch-UM-Dial-Plan-URI-Type",
	"1CE9E84D-9E00-47CF-8175-79BD6AC45F65": "ms-Exch-UM-Dial-Plan-Voip-Security",
	"C7E4D7E8-51C9-478A-B47E-7C494F415A84": "ms-Exch-UM-Disambiguation-Field",
	"4126C33F-8F2B-41E2-A41E-856BA598B8F0": "ms-Exch-UM-DTMF-Fallback-Auto-Attendant-BL",
	"D0101A82-3762-41CB-952A-92B76F3188C3": "ms-Exch-UM-DTMF-Fallback-Auto-Attendant-Link",
	"614AEA82-ABC6-4DD0-A148-D67A59C72816": "ms-Exch-UM-Dtmf-Map",
	"2D485EEE-45E1-4902-ADD1-5630D25D13C2": "ms-Exch-UM-Enabled-Flags",
	"794DA169-B990-4A36-800A-778CC544FE96": "ms-Exch-UM-Enabled-Text",
	"81884566-DD95-4E2A-ADD4-81886429FC37": "ms-Exch-UM-Equivalence-Dial-Plan",
	"E3A943D5-1455-48A3-81F5-682791ACD0DF": "ms-Exch-UM-Extension-Length-Numbers-Allowed",
	"2ABD9BD9-C06D-4DD7-9F77-76E46F6C35BB": "ms-Exch-UM-Fax-Enabled",
	"DCAC508B-52C4-4CF8-B0BE-FA9A422A492A": "ms-Exch-UM-Fax-Id",
	"D4682CA4-BE37-4810-80B1-817B9BB7AA54": "ms-Exch-UM-Fax-Message-Text",
	"7AA1DE79-8152-4570-8362-709D2044BA67": "ms-Exch-UM-Grammar-Generation-Schedule",
	"0B41A421-8532-4A93-B1E3-AA0466C0C545": "ms-Exch-UM-Hunt-Group",
	"CDCCF74C-AA82-402B-A867-6D3ED1F646EC": "ms-Exch-UM-Hunt-Group-Dial-Plan-BL",
	"DB87DADE-2355-451B-866E-874BDAB991B3": "ms-Exch-UM-Hunt-Group-Dial-Plan-Link",
	"98D10A9F-7284-4EC5-A71D-E991814F16A0": "ms-Exch-UM-Hunt-Group-Number",
	"EE86A892-9D7D-4D13-B62A-BA977ED40FA4": "ms-Exch-UM-In-Country-Number-Format",
	"278CC83B-86F0-4D5A-9C39-A5C7BB4A5374": "ms-Exch-UM-Info-Announcement-File",
	"4DE0DA5F-5999-49BF-94C7-62C0D3C8B440": "ms-Exch-UM-Info-Announcement-Status",
	"420EE35E-9C09-40E7-87E2-96576F1288BF": "ms-Exch-UM-Input-Retries",
	"6F0A488E-2B67-4B73-928E-63978C5F01C5": "ms-Exch-UM-Input-Timeout",
	"E5D4865F-E398-4723-8B82-6757BD0E87A4": "ms-Exch-UM-International-Access-Code",
	"2171FDAD-A153-4D30-BA8E-C61114040F0E": "ms-Exch-UM-International-Number-Format",
	"2F786350-069F-46A1-A4A2-A92BBC541915": "ms-Exch-UM-IP-Gateway",
	"F6C99325-C9AC-4621-803A-1686FA91F80D": "ms-Exch-UM-IP-Gateway-Address",
	"ADCA03C2-812A-4BFA-8893-5E9245B4BBCD": "ms-Exch-UM-IP-Gateway-Dial-Plan-BL",
	"8B6CE8AD-6277-451E-BB55-D3BE3BCF2E09": "ms-Exch-UM-IP-Gateway-Dial-Plan-Link",
	"E90E1596-B180-4B6C-BA5D-56DF9756221C": "ms-Exch-UM-IP-Gateway-Flags",
	"4582535E-3200-4CC6-8213-6E463DD5BD42": "ms-Exch-UM-IP-Gateway-Port",
	"D4CFC428-BB85-47AA-8EC1-278CEAC88D68": "ms-Exch-UM-IP-Gateway-Server-BL",
	"DD25EBF7-F122-4AAB-A329-91721632E3FB": "ms-Exch-UM-IP-Gateway-Server-Link",
	"C52024D1-0EC8-47C6-BF01-552AAF5CE5B5": "ms-Exch-UM-IP-Gateway-Status",
	"82408606-C95F-4A2F-A5D8-5BFC5B8D4454": "ms-Exch-UM-List-In-Directory-Search",
	"25B9BC6B-9DBC-43CE-A23D-CBF05A70F3DE": "ms-Exch-UM-Logon-Failures-Before-Disconnect",
	"74BC3ECB-D7AE-4AE4-B333-4CD2015DEF9A": "ms-Exch-UM-Logon-Failures-Before-PIN-Reset",
	"40D8E068-45E2-46B8-B4F9-C5947A712BAE": "ms-Exch-UM-Mailbox-Policy-Dial-Plan-BL",
	"A1D0C37E-190C-4C3E-8D89-AD5CDFEAF154": "ms-Exch-UM-Mailbox-Policy-Dial-Plan-Link",
	"E1C0B4E1-F7B4-4835-91A9-868E09654581": "ms-Exch-UM-Max-Call-Duration",
	"AAF0F4BA-6575-4AD1-BACC-BB8555633ACF": "ms-Exch-UM-Max-Greeting-Duration",
	"7E9B836F-C72A-4CA4-9145-4E1ADA4DA043": "ms-Exch-UM-Maximum-ASR-Sessions-Allowed",
	"2D3FE625-6F64-4C35-AD11-E3A7A2EDFCC2": "ms-Exch-UM-Maximum-Calls-Allowed",
	"DA7B007C-9A9D-4F1E-B1E9-A36F13E7D80F": "ms-Exch-UM-Maximum-Fax-Calls-Allowed",
	"D545BC47-F737-4B36-93EF-1190A3107F52": "ms-Exch-UM-Maximum-TTS-Sessions-Allowed",
	"9D8D29C0-035E-4EDE-A92D-4D49BFEBEC1D": "ms-Exch-UM-Max-Recording-Duration",
	"7BAAF723-7088-4D0F-B44B-DF54DA6689A4": "ms-Exch-UM-National-Number-Prefix",
	"4B957237-17AA-41AC-91EA-C10ABB2AAADF": "ms-Exch-UM-NDR-Req-Enabled",
	"22249203-2D28-47EB-908A-0EEBA73C7846": "ms-Exch-UM-Numbering-Plan-Digits",
	"844D4CFE-F6C9-465C-8AE5-A29A7EE6EB75": "ms-Exch-UM-Operator-Extension",
	"8430C102-39D3-4162-8DB3-2EDF25CD72FC": "ms-Exch-UM-Operator-Number",
	"613B0B02-2659-44ED-BCEC-B65FBE6DDBE4": "ms-Exch-UM-Outcalls-Allowed",
	"871E9FE9-F0A9-4F3D-A41E-C50A287FFA18": "ms-Exch-UM-Override-Extension",
	"CE73E8D2-A5FB-4726-872F-8C5C5ED93FD9": "ms-Exch-UM-Phone-Context",
	"8E035619-633D-41C8-857E-7BC1B4523ECE": "ms-Exch-UM-Pilot-Identifier",
	"3263E3B8-FD6B-4C60-87F2-34BDAA9D69EB": "ms-Exch-UM-Pin-Checksum",
	"7CD75E34-4EED-4C36-9072-C2A56ACE2653": "ms-Exch-UM-Pin-Policy-Account-Lockout-Failures",
	"0B0BB4DB-2314-498E-B31D-A2B35C728785": "ms-Exch-UM-Pin-Policy-Disallow-Common-Patterns",
	"FD574EBB-3A5A-4EB6-BB0D-9871F5F0F3A8": "ms-Exch-UM-Pin-Policy-Expiry-Days",
	"A42F1DD3-9E15-41B3-9455-C70C6BD28D91": "ms-Exch-UM-Pin-Policy-Min-Password-Length",
	"C710A868-29E8-4A98-9F56-D174A62D2A37": "ms-Exch-UM-Pin-Policy-Number-Of-Previous-Passwords-Disallowed",
	"58D9D3B8-2878-49B9-9E97-819D3673957E": "ms-Exch-UM-Query-Base-DN",
	"2A5B8522-D348-49D6-A449-CCAD864575E4": "ms-Exch-UM-Recipient-Dial-Plan-BL",
	"FD75C1D0-0C22-4BD8-95B7-686426C38908": "ms-Exch-UM-Recipient-Dial-Plan-Link",
	"C632FF49-D5DD-4E98-94BA-EF992B548B1F": "ms-Exch-UM-Recipient-Template",
	"4ABA3AF6-4A35-452B-B30A-225584012350": "ms-Exch-UM-Recording-Idle-Timeout",
	"5D088AF5-7397-43EA-9B24-D239997C353E": "ms-Exch-UM-Reset-Password-Value",
	"27D13F09-6F58-435A-8940-8C1DD934C7EE": "ms-Exch-UM-Reset-PIN-Text",
	"EE4C2A9B-6F25-4351-B61F-9AD86A57333D": "ms-Exch-UM-Send-Voice-Message-Enabled",
	"4AAF894C-70CC-4BF1-824F-3E01C6036E9C": "ms-Exch-UM-Send-Voice-Message-Scope",
	"BDD16B37-AF15-48F8-B210-CDD1CCA1373A": "ms-Exch-UM-Server-Dial-Plan-BL",
	"33F4087F-32EA-401B-B5E6-88668DAAE04B": "ms-Exch-UM-Server-Dial-Plan-Link",
	"9AC6D2F7-250C-4DED-8023-FB679C89E270": "ms-Exch-UM-Server-Status",
	"5E353847-F36C-48BE-A7F7-49685402503C": "ms-Exch-UM-Server-Writable-Flags",
	"237DFB6A-5921-4B3E-8FDB-3549F5E604C4": "ms-Exch-UM-Speech-Grammar-Filter-List",
	"2CC06E9D-6F7E-426A-8825-0215DE176E11": "ms-Exch-UM-Spoken-Name",
	"DA3A5720-293F-4499-A7F4-D9A088F9DF25": "ms-Exch-UM-Template-BL",
	"8CD81343-90CA-447B-9A0F-E57376453F55": "ms-Exch-UM-Template-Link",
	"C50DF835-D4BD-4F62-8260-4647E29DBE18": "ms-Exch-UM-Time-Zone",
	"BD82B92C-FAAA-40D2-8F0A-F2C13CA8E927": "ms-Exch-UM-Trunk-Access-Code",
	"C0D365D9-5FCA-456A-A0CC-4C794EFDF19D": "ms-Exch-UM-Virtual-Directory",
	"4B894F61-BD29-4680-9DAE-A26238F896DB": "ms-Exch-UM-Voice-Mail-Originator",
	"E60110EC-966A-4A80-86DE-2BD38624E5F1": "ms-Exch-UM-Voice-Mail-Pilot-Numbers",
	"29BFBEE0-8B87-45C2-8C93-8470194EEB7E": "ms-Exch-UM-Voice-Mail-Text",
	"6E2F83B6-AD2C-436D-A475-40FC0767C770": "ms-Exch-UM-Welcome-Greeting-Enabled",
	"4820EF72-D2BD-40D1-BE57-6FBD7480A5FF": "ms-Exch-UM-Welcome-Greeting-File",
	"8C07DC94-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-UNC-Password",
	"8BE8DE02-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-UNC-Username",
	"A5924AD4-C597-4DB1-8F9D-1799909DC166": "ms-Exch-Unmerged-Atts-Pt",
	"2209550C-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Use-OAB",
	"22428D7C-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Use-OAB-BL",
	"07C31F12-A3E8-4FA0-AF8E-4932C75B2241": "ms-Exch-User-Account-Control",
	"275B2F54-982D-4DCD-B0AD-E53501445EFB": "ms-Exch-User-Culture",
	"1280170A-3E6D-4382-A5EA-3A528E6FF510": "ms-Exch-Version",
	"28009B8E-9876-44F3-B907-A3BF06D3CC1F": "ms-Exch-Virtual-Directory",
	"22770138-B099-11D2-AA06-00C04F8EEDD8": "ms-Exch-Visibility-Mask",
	"567D5200-2F6A-11D3-AA6C-00C04F8EEDD8": "ms-Exch-Voice-Mailbox-ID",
	"2D0977EB-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-VPIM-Convert-Inbound",
	"2D0977F1-2B54-11D3-AA6B-00C04F8EEDD8": "ms-Exch-VPIM-Convert-Outbound",
	"8DF7C5B4-B09E-11D2-AA06-00C04F8EEDD8": "ms-Exch-Web-Access-Name",
	"D34E9D76-5269-4ED9-B91A-2F2A4B20A5CF": "ms-Exch-Web-Services-Virtual-Directory"
}

def ObjectType_to_str(ObjectType:str):
	if ObjectType in ExtendedRightsGUID:
		return ExtendedRightsGUID[ObjectType]
	elif ObjectType in PropertySets:
		return PropertySets[ObjectType]
	elif ObjectType in ValidatedWrites:
		return ValidatedWrites[ObjectType]
	elif ObjectType in MoreGUID:
		return MoreGUID[ObjectType]
	elif ObjectType in MoreGUID_Exchange:
		return MoreGUID_Exchange[ObjectType]
	else:
		return ObjectType

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEType(enum.Enum):	
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE = 0x01
	SYSTEM_AUDIT_ACE_TYPE = 0x02
	SYSTEM_ALARM_ACE_TYPE = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10 
	SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE =0x13

class AceFlags(enum.IntFlag):
	CONTAINER_INHERIT_ACE = 0x02
	FAILED_ACCESS_ACE_FLAG = 0x80
	INHERIT_ONLY_ACE = 0x08
	INHERITED_ACE = 0x10
	NO_PROPAGATE_INHERIT_ACE = 0x04
	OBJECT_INHERIT_ACE = 0x01
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40

# https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)

SDDL_ACE_TYPE_MAPS = {
	"A"  : ACEType.ACCESS_ALLOWED_ACE_TYPE,
	"D"  : ACEType.ACCESS_DENIED_ACE_TYPE,
	"OA" : ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
	"OD" : ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
	"AU" : ACEType.SYSTEM_AUDIT_ACE_TYPE,
	"AL" : ACEType.SYSTEM_ALARM_ACE_TYPE,
	"OU" : ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE,
	"OL" : ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE,
	"ML" : ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE,
	"XA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, #Windows Vista and Windows Server 2003: Not available.
	"XD" : ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE, #Windows Vista and Windows Server 2003: Not available.
	"RA" : ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"SP" : ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"XU" : ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"ZA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, #Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
}
SDDL_ACE_TYPE_MAPS_INV = {v: k for k, v in SDDL_ACE_TYPE_MAPS.items()}

# http://www.coopware.in2.info/_ntfsacl_ht.htm
SDDL_ACE_FLAGS_MAPS = {
	"OI" : AceFlags.OBJECT_INHERIT_ACE, #This folder and files
	"CI" : AceFlags.CONTAINER_INHERIT_ACE, #This folder and subfolders
	"NP" : AceFlags.NO_PROPAGATE_INHERIT_ACE, #Apply these permissions 
	"IO" : AceFlags.INHERIT_ONLY_ACE,
	"ID" : AceFlags.INHERITED_ACE, #inherited
	"SA" : AceFlags.SUCCESSFUL_ACCESS_ACE_FLAG,
	"FA" : AceFlags.FAILED_ACCESS_ACE_FLAG,
}
SDDL_ACE_FLAGS_MAPS_INV = {v: k for k, v in SDDL_ACE_FLAGS_MAPS.items()}
	

def mask_to_str(mask, sd_object_type = None):
	if sd_object_type is None:
		return str(ADS_ACCESS_MASK(mask))
	if sd_object_type == SE_OBJECT_TYPE.SE_FILE_OBJECT:
		return str(FILE_ACCESS_MASK(mask))
	elif sd_object_type == SE_OBJECT_TYPE.SE_SERVICE:
		return str(SERVICE_ACCESS_MASK(mask))
	elif sd_object_type == SE_OBJECT_TYPE.SE_REGISTRY_KEY:
		return str(REGISTRY_ACCESS_MASK(mask))
	else:
		return hex(mask)

def aceflags_to_sddl(flags):
	t = ''
	for k in SDDL_ACE_FLAGS_MAPS_INV:
		if k in flags:
			t += SDDL_ACE_FLAGS_MAPS_INV[k]
	return t

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
well_known_accessmasks = {
	"GR" : 0x80000000,
	"GW" : 0x40000000,
	"GX" : 0x20000000, #GE?
	"GA" : 0x10000000,
	"RC" : 0x00020000,
	"SD" : 0x00010000, # Delete
	"WD" : 0x00040000, # Modify Permissions
	"WO" : 0x00080000, # Modify Owner
	"RP" : 0x00000010, # Read All Properties 	
	"WP" : 0x00000020, # Write All Properties
	"CC" : 0x00000001, # Create All Child Objects
	"DC" : 0x00000002, # Delete All Child Objects
	"LC" : 0x00000004, # List Contents
	"SW" : 0x00000008, # All Validated Writes
	"LO" : 0x00000080, # List Object
	"DT" : 0x00000040, # Delete Subtree
	"CR" : 0x00000100, # All Extended Rights
	"FA" : 0x001f01ff, # File all
	"FX" : 0x001200A0, # File execute
	"FW" : 0x00120116,
	"FR" : 0x00120089,
	"KA" : 0x000f003f, # KEY ALL ACCESS 	 	
	"KR" : 0x00020019, # KEY READ
	"KX" : 0x00020019, # KEY EXECUTE
	"KW" : 0x00020006, # KEY WRITE
}
well_known_accessmasks_inv = {v: k for k, v in well_known_accessmasks.items()}
def accessmask_to_sddl(mask, sd_object_type):
	if mask in well_known_accessmasks_inv:
		return well_known_accessmasks_inv[mask]
	else:
		return hex(mask) 

def sddl_to_accessmask(mask_str):
	if mask_str in well_known_accessmasks:
		return well_known_accessmasks[mask_str]
	else:
		return int(mask_str, 16)

class ACE:
	def __init__(self):
		pass

	@staticmethod
	def from_bytes(data, sd_object_type = None):
		return ACE.from_buffer(io.BytesIO(data), sd_object_type)

	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		hdr = ACEHeader.pre_parse(buff)
		obj = acetype2ace.get(hdr.AceType)
		if not obj:
			raise Exception('ACE type %s not implemented!' % hdr.AceType)
		return obj.from_buffer(io.BytesIO(buff.read(hdr.AceSize)), sd_object_type)

	def to_buffer(self, buff):
		pass

	def to_bytes(self) -> bytes:
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_sddl(self, sd_object_type = None):
		pass
	
	@staticmethod
	def from_sddl(sddl:str, object_type = None, domain_sid = None):

		if sddl.startswith('('):
			sddl = sddl[1:]
		if sddl.endswith(')'):
			sddl = sddl[:-1]
		
		ace_type, ace_flags_str, rights, object_guid, inherit_object_guid, account_sid = sddl.split(';')

		ace_type = SDDL_ACE_TYPE_MAPS[ace_type]
		ace_flags = 0
		for i in range(0, len(ace_flags_str), 2):
			ace_flags |= SDDL_ACE_FLAGS_MAPS[ace_flags_str[i:i+2]]
		
		ace = acetype2ace[ace_type]()
		ace.AceFlags = AceFlags(ace_flags)
		ace.Mask = sddl_to_accessmask(rights)
		ace.Flags = 0
		ace.Sid = SID.from_sddl(account_sid, domain_sid = domain_sid)
		ace.sd_object_type = object_type

		if object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
			ace.ObjectType = GUID.from_string(object_guid)
		if inherit_object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT
			ace.InheritedObjectType = GUID.from_string(inherit_object_guid)

		return ace

	@staticmethod
	def add_padding(x):
		if (4 + len(x)) % 4 != 0:
			x += b'\x00' * ((4 + len(x)) % 4)
		return x

class ACCESS_ALLOWED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = 0
		self.Mask = None
		self.Sid = None
		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		ace = ACCESS_ALLOWED_ACE()
		ace.sd_object_type = SE_OBJECT_TYPE(sd_object_type) if sd_object_type else None
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)

	def __str__(self):
		t = 'ACCESS_ALLOWED_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
class ACCESS_DENIED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	
	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)
	
	def __str__(self):
		t = 'ACCESS_DENIED_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
class SYSTEM_AUDIT_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_AUDIT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)
	
	def __str__(self):
		t = 'SYSTEM_AUDIT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
class SYSTEM_ALARM_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_ALARM_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_ALARM_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			'',
			'', 
			self.Sid.to_sddl()  
		)
	
	def __str__(self):
		t = 'SYSTEM_ALARM_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)		
		return t
		
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ACE_OBJECT_PRESENCE(enum.IntFlag):
	NONE = 0x00000000 #Neither ObjectType nor InheritedObjectType are valid.
	ACE_OBJECT_TYPE_PRESENT = 0x00000001 #ObjectType is valid.
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 #InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.

class ACCESS_ALLOWED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_ALLOWED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
			self.Sid.to_sddl()  
		)
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % ObjectType_to_str(str(self.ObjectType))
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_DENIED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, sd_object_type = None):
		#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % ( 
			SDDL_ACE_TYPE_MAPS_INV[self.AceType], 
			aceflags_to_sddl(self.AceFlags), 
			accessmask_to_sddl(self.Mask, self.sd_object_type),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
			self.Sid.to_sddl()  
		)
		
	def __str__(self):
		t = 'ACCESS_DENIED_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % ObjectType_to_str(str(self.ObjectType))
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class SYSTEM_AUDIT_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None #must be bytes!
		

		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_OBJECT_ACE()
		ace.sd_object_type  = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
	
	# def to_sddl(self, sd_object_type = None):
	# 	#ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
	# 	return '(%s;%s;%s;%s;%s;%s)' % ( 
	# 		SDDL_ACE_TYPE_MAPS_INV[self.Header.AceType], 
	# 		aceflags_to_sddl(self.Header.AceFlags), 
	# 		accessmask_to_sddl(self.Mask, self.sd_object_type),
	# 		self.ObjectType.to_bytes() if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
	# 		self.InheritedObjectType.to_bytes() if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '', 
	# 		self.Sid.to_sddl()  
	# 	)

	def to_sddl(self, sd_object_type=None):
		"""
		Convert SYSTEM_AUDIT_OBJECT_ACE to SDDL format.
		
		Args:
			sd_object_type: Security descriptor object type for mask conversion
			
		Returns:
			str: SDDL string in format (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid)
		"""
		obj_type = sd_object_type or self.sd_object_type
		
		# ACE type (AU for System Audit)
		ace_type = SDDL_ACE_TYPE_MAPS_INV.get(self.AceType, 'AU')
		
		# ACE flags
		ace_flags = aceflags_to_sddl(self.AceFlags) if self.AceFlags else ''
		
		# Access mask (rights)
		rights = accessmask_to_sddl(self.Mask, obj_type) if self.Mask else ''
		
		# Object GUID
		object_guid = ''
		if self.Flags and (self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT) and self.ObjectType:
			object_guid = str(self.ObjectType)
		
		# Inherited object GUID
		inherited_guid = ''
		if self.Flags and (self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT) and self.InheritedObjectType:
			inherited_guid = str(self.InheritedObjectType)
		
		# Account SID
		sid = self.Sid.to_sddl() if self.Sid else ''
		
		return f'({ace_type};{ace_flags};{rights};{object_guid};{inherited_guid};{sid})'
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % ObjectType_to_str(str(self.ObjectType))
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'AccessControlType: Allow\r\n'
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_DENIED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % ObjectType_to_str(str(self.ObjectType))
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class ACCESS_DENIED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'ACCESS_DENIED_CALLBACK_OBJECT_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ObjectType: %s\r\n' % ObjectType_to_str(str(self.ObjectType))
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None
		
		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace
	
	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()
		
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE\r\n'
		t += 'ObjectType: %s\r\n' % self.ObjectType
		t += 'InheritedObjectType: %s\r\n' % self.InheritedObjectType
		t += 'ObjectFlags: %s\r\n' % self.Flags
		t += 'ApplicationData: %s \r\n' % self.ApplicationData
		
		return t
		
class SYSTEM_MANDATORY_LABEL_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_MANDATORY_LABEL_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
class SYSTEM_RESOURCE_ATTRIBUTE_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.AttributeData = None #must be bytes for now. structure is TODO (see top of file)
		
		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_RESOURCE_ATTRIBUTE_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.AttributeData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)		
		t += self.Sid.to_bytes()
		t += self.AttributeData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)
		
	def __str__(self):
		t = 'SYSTEM_RESOURCE_ATTRIBUTE_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)
		t += 'AttributeData: %s \r\n' % self.AttributeData
		
		return t
		
class SYSTEM_SCOPED_POLICY_ID_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None
		
	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_SCOPED_POLICY_ID_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4,'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def __str__(self):
		t = 'SYSTEM_SCOPED_POLICY_ID_ACE\r\n'
		t += 'Flags: %s\r\n' % str(self.AceFlags)
		t += 'Sid: %s\r\n' % self.Sid
		t += 'Mask: %s\r\n' % mask_to_str(self.Mask, self.sd_object_type)

		return t
		
acetype2ace:Dict[ACEType, ACE] = { #TODO: type hint not correct
	ACEType.ACCESS_ALLOWED_ACE_TYPE : ACCESS_ALLOWED_ACE,
	ACEType.ACCESS_DENIED_ACE_TYPE : ACCESS_DENIED_ACE,
	ACEType.SYSTEM_AUDIT_ACE_TYPE : SYSTEM_AUDIT_ACE,
	ACEType.SYSTEM_ALARM_ACE_TYPE : SYSTEM_ALARM_ACE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE,
	ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_DENIED_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE : SYSTEM_AUDIT_OBJECT_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE : ACCESS_DENIED_CALLBACK_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_DENIED_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE : SYSTEM_MANDATORY_LABEL_ACE,
	ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE : SYSTEM_RESOURCE_ATTRIBUTE_ACE,
	ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE : SYSTEM_SCOPED_POLICY_ID_ACE,
	}
"""
ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : , # reserved
ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : ,# reserved
ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : ,# reserved

"""

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEHeader:
	def __init__(self):
		self.AceType:ACEType = None
		self.AceFlags:AceFlags = None
		self.AceSize:int = None

	def to_buffer(self, buff):
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		
	@staticmethod
	def from_bytes(data):
		return ACEHeader.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		return hdr
		
	@staticmethod
	def pre_parse(buff):
		pos = buff.tell()
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = AceFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		buff.seek(pos,0)
		return hdr
