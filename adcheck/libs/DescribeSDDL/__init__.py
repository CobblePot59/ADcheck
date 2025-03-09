#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DescribeNTSecurityDescriptor.py
# Author             : Podalirius (@podalirius_)
# Date created       : 09 April 2024

import re
from enum import IntFlag, Enum


VERSION = "1.1"


# https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
enum_sid_names = {
    "AA": "Access control assistance operators",
    "AC": "All applications running in an app package context",
    "AN": "Anonymous logon",
    "AO": "Account operators",
    "AP": "Protected Users",
    "AU": "Authenticated users",
    "BA": "Built-in administrators",
    "BG": "Built-in guests",
    "BO": "Backup operators",
    "BU": "Built-in users",
    "CA": "Certificate publishers",
    "CD": "Users who can connect to certification authorities using DCOM",
    "CG": "Creator group",
    "CN": "Cloneable domain controllers",
    "CO": "Creator owner",
    "CY": "Crypto operators",
    "DA": "Domain administrators",
    "DC": "Domain computers",
    "DD": "Domain controllers",
    "DG": "Domain guests",
    "DU": "Domain users",
    "EA": "Enterprise administrators",
    "ED": "Enterprise domain controllers",
    "EK": "Enterprise key admins",
    "ER": "Event log readers",
    "ES": "Endpoint servers",
    "HA": "Hyper-V administrators",
    "HI": "High integrity level",
    "HO": "User mode hardware operators",
    "IS": "Anonymous Internet users",
    "IU": "Interactively logged-on user",
    "KA": "Domain key admins",
    "LA": "Local administrator",
    "LG": "Local guest",
    "LS": "Local service account",
    "LU": "Performance Log users",
    "LW": "Low integrity level",
    "ME": "Medium integrity level",
    "MP": "Medium Plus integrity level",
    "MU": "Performance Monitor users",
    "NO": "Network configuration operators",
    "NS": "Network service account",
    "NU": "Network logon user",
    "OW": "Owner Rights SID",
    "PA": "Group Policy administrators",
    "PO": "Printer operators",
    "PS": "Principal self",
    "PU": "Power users",
    "RA": "RDS remote access servers",
    "RC": "Restricted code",
    "RD": "Terminal server users",
    "RE": "Replicator",
    "RM": "RMS Service operators",
    "RO": "Enterprise Read-only domain controllers",
    "RS": "RAS servers group",
    "RU": "Alias to grant permissions to accounts that use applications compatible with operating systems previous to Windows 2000",
    "SA": "Schema administrators",
    "SI": "System integrity level",
    "SO": "Server operators",
    "SS": "Authentication service asserted",
    "SU": "Service logon user",
    "SY": "Local system",
    "UD": "User-mode driver",
    "WD": "Everyone",
    "WR": "Write Restricted code"
}


wellKnownSIDs =  {
    "S-1-5-1": "Dialup",
    "S-1-5-113": "Local account",
    "S-1-5-114": "Local account and member of Administrators group",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    # "S-1-5-5-X-Y": "Logon Session",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server User",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "System (or LocalSystem)",
    "S-1-5-19": "NT Authority (LocalService)",
    "S-1-5-20": "Network Service",
    # "S-1-5-domain-500": "Administrator",
    # "S-1-5-domain-501": "Guest",
    # "S-1-5-domain-502": "KRBTGT",
    # "S-1-5-domain-512": "Domain Admins",
    # "S-1-5-domain-513": "Domain Users",
    # "S-1-5-domain-514": "Domain Guests",
    # "S-1-5-domain-515": "Domain Computers",
    # "S-1-5-domain-516": "Domain Controllers",
    # "S-1-5-domain-517": "Cert Publishers",
    # "S-1-5-root domain-518": "Schema Admins",
    # "S-1-5-root domain-519": "Enterprise Admins",
    # "S-1-5-domain-520": "Group Policy Creator Owners",
    # "S-1-5-domain-521": "Read-only Domain Controllers",
    # "S-1-5-domain-522": "Clonable Controllers",
    # "S-1-5-domain-525": "Protected Users",
    # "S-1-5-root domain-526": "Key Admins",
    # "S-1-5-domain-527": "Enterprise Key Admins",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    # "S-1-5-domain-553": "RAS and IAS Servers",
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
    # "S-1-5-domain-571": "Allowed RODC Password Replication Group",
    # "S-1-5-domain-572": "Denied RODC Password Replication Group",
    "S-1-5-32-573": "Builtin\\Event Log Readers",
    "S-1-5-32-574": "Builtin\\Certificate Service DCOM Access",
    "S-1-5-32-575": "Builtin\\RDS Remote Access Servers",
    "S-1-5-32-576": "Builtin\\RDS Endpoint Servers",
    "S-1-5-32-577": "Builtin\\RDS Management Servers",
    "S-1-5-32-578": "Builtin\\Hyper-V Administrators",
    "S-1-5-32-579": "Builtin\\Access Control Assistance Operators",
    "S-1-5-32-580": "Builtin\\Remote Management Users",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-80": "NT Service",
    "S-1-5-80-0": "All Services",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-15-2-1": "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
    # "S-1-15-3-…": "All capability SIDs start with S-1-15-3.",
    # "S-1-16-…": "Mandatory Level See processes: integrity levels",
    "S-1-18-1": "Authentication authority asserted identity"
}


enum_ace_types = {
    "A": "ACCESS_ALLOWED_ACE_TYPE",
    "D": "ACCESS_DENIED_ACE_TYPE",
    "OA": "ACCESS_ALLOWED_OBJECT_ACE_TYPE",
    "OD": "ACCESS_DENIED_OBJECT_ACE_TYPE",
    "AU": "SYSTEM_AUDIT_ACE_TYPE",
    "AL": "SYSTEM_ALARM_ACE_TYPE",
    "OU": "SYSTEM_AUDIT_OBJECT_ACE_TYPE",
    "OL": "SYSTEM_ALARM_OBJECT_ACE_TYPE",
    "ML": "SYSTEM_MANDATORY_LABEL_ACE_TYPE",
    "XA": "ACCESS_ALLOWED_CALLBACK_ACE_TYPE",
    "XD": "ACCESS_DENIED_CALLBACK_ACE_TYPE",
    "RA": "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE",
    "SP": "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE",
    "XU": "SYSTEM_AUDIT_CALLBACK_ACE_TYPE",
    "ZA": "ACCESS_ALLOWED_CALLBACK_ACE_TYPE",
    "TL": "SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE",
    "FL": "SYSTEM_ACCESS_FILTER_ACE_TYPE"
}


enum_ace_flags = {
    "CI": "CONTAINER_INHERIT_ACE",
    "OI": "OBJECT_INHERIT_ACE",
    "NP": "NO_PROPAGATE_INHERIT_ACE",
    "IO": "INHERIT_ONLY_ACE",
    "ID": "INHERITED_ACE",
    "SA": "SUCCESSFUL_ACCESS_ACE_FLAG",
    "FA": "FAILED_ACCESS_ACE_FLAG",
    "TP": "TRUST_PROTECTED_FILTER_ACE_FLAG",
    "CR": "CRITICAL_ACE_FLAG"
}


enum_ace_rights = {
    # Generic access rights
    "GA": "GENERIC_ALL",
    "GR": "GENERIC_READ",
    "GW": "GENERIC_WRITE",
    "GX": "GENERIC_EXECUTE",
    
    # Standard access rights
    "RC": "READ_CONTROL",
    "SD": "DELETE",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",
    
    # Directory service object access rights
    "RP": "ADS_RIGHT_DS_READ_PROP",
    "WP": "ADS_RIGHT_DS_WRITE_PROP",
    "CC": "ADS_RIGHT_DS_CREATE_CHILD",
    "DC": "ADS_RIGHT_DS_DELETE_CHILD",
    "LC": "ADS_RIGHT_ACTRL_DS_LIST",
    "SW": "ADS_RIGHT_DS_SELF",
    "LO": "ADS_RIGHT_DS_LIST_OBJECT",
    "DT": "ADS_RIGHT_DS_DELETE_TREE",
    "CR": "ADS_RIGHT_DS_CONTROL_ACCESS",
    
    # File access rights
    "FA": "FILE_GENERIC_ALL",
    "FR": "FILE_GENERIC_READ",
    "FW": "FILE_GENERIC_WRITE",
    "FX": "FILE_GENERIC_EXECUTE",
    
    # Registry key access rights
    "KA": "KEY_ALL_ACCESS",
    "KR": "KEY_READ",
    "KW": "KEY_WRITE",
    "KX": "KEY_EXECUTE",
    
    # Mandatory label rights
    "NR": "SYSTEM_MANDATORY_LABEL_NO_READ_UP",
    "NW": "SYSTEM_MANDATORY_LABEL_NO_WRITE_UP",
    "NX": "SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP"
}


class AccessMaskFlags(IntFlag):
    """
    AccessMaskFlags: Enum class that defines constants for access mask flags.

    This class defines constants for various access mask flags as specified in the Microsoft documentation. These flags represent permissions or rights that can be granted or denied for security principals in access control entries (ACEs) of an access control list (ACL).

    The flags include permissions for creating or deleting child objects, listing contents, reading or writing properties, deleting a tree of objects, and controlling access. Additionally, it includes generic rights like GENERIC_ALL, GENERIC_EXECUTE, GENERIC_WRITE, and GENERIC_READ.

    The values for these flags are derived from the following Microsoft documentation sources:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
    - https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum

    Attributes:
        DS_CREATE_CHILD (int): Permission to create child objects.
        DS_DELETE_CHILD (int): Permission to delete child objects.
        DS_LIST_CONTENTS (int): Permission to list contents.
        DS_WRITE_PROPERTY_EXTENDED (int): Permission to write properties (extended).
        DS_READ_PROPERTY (int): Permission to read properties.
        DS_WRITE_PROPERTY (int): Permission to write properties.
        DS_DELETE_TREE (int): Permission to delete a tree of objects.
        DS_LIST_OBJECT (int): Permission to list objects.
        DS_CONTROL_ACCESS (int): Permission for access control.
        DELETE (int): Permission to delete.
        READ_CONTROL (int): Permission to read security descriptor.
        WRITE_DAC (int): Permission to modify discretionary access control list (DACL).
        WRITE_OWNER (int): Permission to change the owner.
        GENERIC_ALL (int): Generic all permissions.
        GENERIC_EXECUTE (int): Generic execute permissions.
        GENERIC_WRITE (int): Generic write permissions.
        GENERIC_READ (int): Generic read permissions.
    """

    DS_CREATE_CHILD = 0x00000001
    DS_DELETE_CHILD = 0x00000002
    DS_LIST_CONTENTS = 0x00000004
    DS_WRITE_PROPERTY_EXTENDED = 0x00000008
    DS_READ_PROPERTY = 0x00000010
    DS_WRITE_PROPERTY = 0x00000020
    DS_DELETE_TREE = 0x00000040
    DS_LIST_OBJECT = 0x00000080
    DS_CONTROL_ACCESS = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    # Generic rights
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000


class PropertySet(Enum):
    """
    PropertySet is an enumeration of GUIDs representing various property sets in Active Directory.
    These property sets group related properties of AD objects, making it easier to manage and apply permissions to these properties.
    Each entry in this enumeration maps a human-readable name to the corresponding GUID of the property set.
    These GUIDs are used in Access Control Entries (ACEs) to grant or deny permissions to read or write a set of properties on AD objects.

    The GUIDs are defined by Microsoft and can be found in the Microsoft documentation and technical specifications.
    Property sets are a crucial part of the Active Directory schema and help in defining the security model by allowing fine-grained access control.

    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca
    """
    DOMAIN_PASSWORD_AND_LOCKOUT_POLICIES = "c7407360-20bf-11d0-a768-00aa006e0529"
    GENERAL_INFORMATION = "59ba2f42-79a2-11d0-9020-00c04fc2d3cf"
    ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"
    LOGON_INFORMATION = "5f202010-79a5-11d0-9020-00c04fc2d4cf"
    GROUP_MEMBERSHIP = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
    PHONE_AND_MAIL_OPTIONS = "e45795b2-9455-11d1-aebd-0000f80367c1"
    PERSONAL_INFORMATION = "77b5b886-944a-11d1-aebd-0000f80367c1"
    WEB_INFORMATION = "e45795b3-9455-11d1-aebd-0000f80367c1"
    PUBLIC_INFORMATION = "e48d0154-bcf8-11d1-8702-00c04fb96050"
    REMOTE_ACCESS_INFORMATION = "037088f8-0ae1-11d2-b422-00a0c968f939"
    OTHER_DOMAIN_PARAMETERS_FOR_USE_BY_SAM = "b8119fd0-04f6-4762-ab7a-4986c76b3f9a"
    DNS_HOST_NAME_ATTRIBUTES = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
    MS_TS_GATEWAYACCESS = "ffa6f046-ca4b-4feb-b40d-04dfee722543"
    PRIVATE_INFORMATION = "91e647de-d96f-4b70-9557-d63ff4f3ccd8"
    TERMINAL_SERVER_LICENSE_SERVER = "5805bc62-bdc9-4428-a5e2-856a0f4c185e"


class ExtendedRights(Enum):
    """
    ExtendedRights is an enumeration of GUIDs representing various extended rights in Active Directory.
    These rights are associated with specific operations that can be performed on AD objects.
    Each entry in this enumeration maps a human-readable name to the corresponding GUID of the extended right.
    These GUIDs are used in Access Control Entries (ACEs) to grant or deny these rights to security principals (users, groups, etc.).

    The rights include, but are not limited to, the ability to create or delete specific types of child objects,
    force password resets, read/write specific properties, and more. They play a crucial role in defining
    the security model of Active Directory by allowing fine-grained access control to objects.

    The GUIDs are defined by Microsoft and can be found in the Microsoft documentation and technical specifications.

    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/443fe66f-c9b7-4c50-8c24-c708692bbf1d
    """

    # 
    ABANDON_REPLICATION = "ee914b82-0a98-11d1-adbb-00c04fd8d5cd"
	#
    ADD_GUID = "440820ad-65b4-11d1-a3da-0000f875ae0d"
	#
    ALLOCATE_RIDS = "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd"
	#
    ALLOWED_TO_AUTHENTICATE = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"
	#
    APPLY_GROUP_POLICY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
    # 
    CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	# 
    CHANGE_DOMAIN_MASTER = "014bf69c-7b3b-11d1-85f6-08002be74fab"
	# 
    CHANGE_INFRASTRUCTURE_MASTER = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd"
	# 
    CHANGE_PDC = "bae50096-4752-11d1-9052-00c04fc2d4cf"
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fcb2b5e7-302f-43cb-8adf-4c9cd9423178
    CHANGE_RID_MASTER = "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd"
	# 
    CHANGE_SCHEMA_MASTER = "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd"
	# 
    CREATE_INBOUND_FOREST_TRUST = "e2a36dc9-ae17-47c3-b58b-be34c55ba633"
	# 
    DO_GARBAGE_COLLECTION = "fec364e0-0a98-11d1-adbb-00c04fd8d5cd"
	# 
    DOMAIN_ADMINISTER_SERVER = "ab721a52-1e2f-11d0-9819-00aa0040529b"
	# 
    DS_CHECK_STALE_PHANTOMS = "69ae6200-7f46-11d2-b9ad-00c04f79f805"
	# 
    DS_CLONE_DOMAIN_CONTROLLER = "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e"
	# 
    DS_EXECUTE_INTENTIONS_SCRIPT = "2f16c4a5-b98e-432c-952a-cb388ba33f2e"
	# 
    DS_INSTALL_REPLICA = "9923a32a-3607-11d2-b9be-0000f87a36b2"
	# 
    DS_QUERY_SELF_QUOTA = "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc"
	# 
    DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"
	# 
    DS_REPLICATION_MANAGE_TOPOLOGY = "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    DS_REPLICATION_MONITOR_TOPOLOGY = "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96"
	# 
    DS_REPLICATION_SYNCHRONIZE = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD = "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5"
	# 
    GENERATE_RSOP_LOGGING = "b7b1b3de-ab09-4242-9e30-9980e5d322f7"
	# 
    GENERATE_RSOP_PLANNING = "b7b1b3dd-ab09-4242-9e30-9980e5d322f7"
	# 
    MANAGE_OPTIONAL_FEATURES = "7c0e2a7c-a419-48e4-a995-10180aad54dd"
	# 
    MIGRATE_SID_HISTORY = "ba33815a-4f93-4c76-87f3-57574bff8109"
	# 
    MSMQ_OPEN_CONNECTOR = "b4e60130-df3f-11d1-9c86-006008764d0e"
	# 
    MSMQ_PEEK = "06bd3201-df3e-11d1-9c86-006008764d0e"
	# 
    MSMQ_PEEK_COMPUTER_JOURNAL = "4b6e08c3-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_PEEK_DEAD_LETTER = "4b6e08c1-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE = "06bd3200-df3e-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE_COMPUTER_JOURNAL = "4b6e08c2-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE_DEAD_LETTER = "4b6e08c0-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE_JOURNAL = "06bd3203-df3e-11d1-9c86-006008764d0e"
	# 
    MSMQ_SEND = "06bd3202-df3e-11d1-9c86-006008764d0e"
	# 
    OPEN_ADDRESS_BOOK = "a1990816-4298-11d1-ade2-00c04fd8d5cd"
	# 
    READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION = "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    REANIMATE_TOMBSTONES = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"
	# 
    RECALCULATE_HIERARCHY = "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd"
	# 
    RECALCULATE_SECURITY_INHERITANCE = "62dd28a8-7f46-11d2-b9ad-00c04f79f805"
	# 
    RECEIVE_AS = "ab721a56-1e2f-11d0-9819-00aa0040529b"
	# 
    REFRESH_GROUP_CACHE = "9432c620-033c-4db7-8b58-14ef6d0bf477"
	# 
    RELOAD_SSL_CERTIFICATE = "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8"
	# 
    RUN_PROTECT_ADMIN_GROUPS_TASK = "7726b9d5-a4b4-4288-a6b2-dce952e80a7f"
	# 
    SAM_ENUMERATE_ENTIRE_DOMAIN = "91d67418-0135-4acc-8d79-c08e857cfbec"
	# 
    SEND_AS = "ab721a54-1e2f-11d0-9819-00aa0040529b"
	# 
    SEND_TO = "ab721a55-1e2f-11d0-9819-00aa0040529b"
	# 
    UNEXPIRE_PASSWORD = "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"
	# 
    UPDATE_PASSWORD_NOT_REQUIRED_BIT = "280f369c-67c7-438e-ae98-1d46f3c6f541"
	# 
    UPDATE_SCHEMA_CACHE = "be2bb760-7f46-11d2-b9ad-00c04f79f805"
	# 
    USER_CHANGE_PASSWORD = "ab721a53-1e2f-11d0-9819-00aa0040529b"
	# 
    USER_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"


def resolveNameFromGuid(objectGuid):
    name = None
    # Parse Extended Rights
    if objectGuid in [_.value for _ in ExtendedRights]:
        name = "Extended Right %s" % ExtendedRights(value=objectGuid).name
    # Parse Property Set
    elif objectGuid in [_.value for _ in PropertySet]:
        name = "Property Set %s" % PropertySet(value=objectGuid).name
    # Default to the original guid
    else:
        name = objectGuid
    return name


def parseACE(ace_string):
    ace = {}

    elements = ace_string.split(';')

    ace_type = elements[0]
    ace_flags = elements[1]
    rights = elements[2]
    object_guid = elements[3]
    inherit_object_guid = elements[4]
    account_sid = elements[5]
    resource_attribute = None
    if len(elements) == 7:
        resource_attribute = elements[6]
        ace["Ressource"] = None

    # AceType
    if ace_type in enum_ace_types.keys():
        ace["AceType"] = enum_ace_types[ace_type]
    else:
        ace["AceType"] = ace_type

    # AceFlags
    ace["AceFlags"] = []
    for i in range(0, len(ace_flags), 2):
        value = ace_flags[i:i+2]
        if value in enum_ace_flags.keys():
            ace["AceFlags"].append(enum_ace_flags[value])
        else:
            ace["AceFlags"].append(value)

    # Rights
    ace["Rights"] = []
    if re.match(pattern="^0x[0-9a-f]+$", string=rights, flags=re.IGNORECASE):
        for v in AccessMaskFlags(int(rights, 16)):
            ace["Rights"].append(v.name)
    else:
        for i in range(0, len(rights), 2):
            value = rights[i:i+2]
            if value in enum_ace_rights.keys():
                ace["Rights"].append(enum_ace_rights[value])
            else:
                ace["Rights"].append(value)

    # ObjectGuid
    if len(object_guid) != 0:
        ace["ObjectGuid"] = resolveNameFromGuid(object_guid)

    # InheritedObjectGuid
    if len(inherit_object_guid) != 0:
        ace["InheritedObjectGuid"] = resolveNameFromGuid(inherit_object_guid)

    # SID
    if account_sid in enum_sid_names.keys():
        ace["SID"] = enum_sid_names[account_sid]
    elif account_sid in wellKnownSIDs.keys():
        ace["SID"] = wellKnownSIDs[account_sid]
    else:
        ace["SID"] = account_sid

    return ace


def parse_SDDL(sddl_string):
    parsed_sd = {
        "DACL": [],
        "SACL": [],
        "Owner SID": None,
        "Group SID": None
    }
    sddl_string = sddl_string.replace("O:","\nO:")
    sddl_string = sddl_string.replace("G:","\nG:")
    sddl_string = sddl_string.replace("D:","\nD:")
    sddl_string = sddl_string.replace("S:","\nS:")
    sddl_string = sddl_string.strip().split('\n')
    sddl_string = {line.split(':',1)[0]:line.split(':',1)[1] for line in sddl_string}

    # Parsing Owner
    if "O" in sddl_string.keys():
        v = sddl_string["O"]
        if v in enum_sid_names.keys():
            parsed_sd["Owner SID"] = enum_sid_names[v]
        else:
            parsed_sd["Owner SID"] = v

    # Parsing Group
    if "G" in sddl_string.keys():
        v = sddl_string["G"]
        if v in enum_sid_names.keys():
            parsed_sd["Group SID"] = enum_sid_names[v]
        else:
            parsed_sd["Group SID"] = v

    # Parsing DACL
    if "D" in sddl_string.keys():
        aces = re.findall(pattern=r"\(([^)]*)\)", string=sddl_string["D"], flags=re.IGNORECASE)
        for ace_string in aces:
            parsed_sd["DACL"].append(parseACE(ace_string))

    # Parsing SACL
    if "S" in sddl_string.keys():
        aces = re.findall(pattern=r"\(([^)]*)\)", string=sddl_string["S"], flags=re.IGNORECASE)
        for ace_string in aces:
            parsed_sd["DACL"].append(parseACE(ace_string))

    return parsed_sd