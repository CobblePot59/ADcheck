from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from adcheck.modules.constants import ENTRANCE_ACCESS_CONTROL, REGISTRY_ACCESS_RIGHT, LAPS_PROPERTIES_UUID, REGISTRY_ACCESS_INHERITED, DELEGATIONS_ACE
import json
import base64

class SecurityDescriptorParser:
    def __init__(self, new_well_known_sids, schema_objects, schema_attributes, extended_rights, all_entries, object_type):
        self.new_well_known_sids = new_well_known_sids
        self.schema_objects = schema_objects
        self.schema_attributes = schema_attributes
        self.extended_rights = extended_rights
        self.all_entries = all_entries
        self.object_type = object_type

    @staticmethod
    def get_encoded_attr(encoded_attr):
        decoded_attr = base64.b64decode(json.loads(encoded_attr.replace('\'', '"'))['encoded'])
        return decoded_attr

    def ace_details(self, _object):
        if self.object_type == 'container':
            security_descriptor = SR_SECURITY_DESCRIPTOR()
            security_descriptor.fromString(self.get_encoded_attr(_object['nTSecurityDescriptor']))
        elif self.object_type == 'reg_key':
            security_descriptor = SR_SECURITY_DESCRIPTOR(_object)

        def get_formatted_sid(ace):
            sid = ace['Ace']['Sid'].formatCanonical()
            formatted_sid = self.new_well_known_sids.get(sid) \
                or (self.new_well_known_sids.get('S-1-5-5') if sid.startswith('S-1-5-5') else None) \
                or next((entry['sAMAccountName'] for entry in self.all_entries if 'objectSid' in entry and sid == entry['objectSid']), None) \
                or sid
            return formatted_sid

        def calculate_permissions(mask):
            if self.object_type == 'container':
                ACCESS_CONTROL = ENTRANCE_ACCESS_CONTROL
            elif self.object_type == 'reg_key':
                ACCESS_CONTROL = REGISTRY_ACCESS_RIGHT
            else:
                return []

            if mask == ACCESS_CONTROL['Full Control']:
                permissions = 'Full Control'
            elif self.object_type == 'reg_key' and mask == ACCESS_CONTROL['Read']:
                permissions = 'Read'
            else:
                permissions = []
                for attribute, bitmask in ACCESS_CONTROL.items():
                    if int(mask) & bitmask and attribute not in ('Full Control', 'Read'):
                        permissions.append(attribute)
            return permissions

        def get_advanced_properties(ace):
            if ace['TypeName'] == 'ACCESS_ALLOWED_OBJECT_ACE' or ace['TypeName'] == 'ACCESS_DENIED_OBJECT_ACE':
                _uuid = ace['Ace']['ObjectType']
                _uuid_hex = str(_uuid.hex())
                _uuid_hex = '-'.join([_uuid_hex[:8], _uuid_hex[8:12], _uuid_hex[12:16], _uuid_hex[16:20], _uuid_hex[20:]])
                rights_guid = '{}{}{}{}-{}{}-{}{}-{}-{}'.format(
                    _uuid_hex[6:8], _uuid_hex[4:6], _uuid_hex[2:4], _uuid_hex[0:2],
                    _uuid_hex[11:13], _uuid_hex[9:11], _uuid_hex[16:18], _uuid_hex[14:16],
                    _uuid_hex[19:23], _uuid_hex[24:]
                )
                advanced_properties = [schema_object['name'] for schema_object in self.schema_objects if str(self.get_encoded_attr(schema_object['schemaIDGUID'])) == str(_uuid)] \
                    or [schema_attribute['name'] for schema_attribute in self.schema_attributes if str(self.get_encoded_attr(schema_attribute['schemaIDGUID'])) == str(_uuid)] \
                    or [extended_right['displayName'] for extended_right in self.extended_rights if extended_right['rightsGuid'] == rights_guid] \
                    or [key for key, value in LAPS_PROPERTIES_UUID.items() if str(value) == str(_uuid)]
                return advanced_properties

        def get_inherited(ace):
            if self.object_type == 'container':
                if ace['TypeName'] == 'ACCESS_ALLOWED_OBJECT_ACE' or ace['TypeName'] == 'ACCESS_DENIED_OBJECT_ACE':
                    if len(ace['Ace']['InheritedObjectType']) > 0:
                        descendant = [schema_object['name'] for schema_object in self.schema_objects if str(self.get_encoded_attr(schema_object['schemaIDGUID'])) == str(ace['Ace']['InheritedObjectType'])]
                        return descendant
            elif self.object_type == 'reg_key':
                return REGISTRY_ACCESS_INHERITED.get(ace['AceFlags'])

        if self.object_type == 'container':
            security_info = {
                'Owner': self.new_well_known_sids.get(security_descriptor['OwnerSid'].formatCanonical()),
                'GroupOwner': self.new_well_known_sids.get(security_descriptor['GroupSid'].formatCanonical()),
                'Sacl': [
                    {
                        'User': get_formatted_sid(ace),
                        'Permissions': {
                            'PermissionsType': ace['TypeName'],
                            'PermissionsValue': calculate_permissions(ace['Ace']['Mask']['Mask']),
                            'PermissionsObjects': get_advanced_properties(ace),
                            'InheritedObjectType': get_inherited(ace)
                        }
                    }
                    for ace in security_descriptor['Sacl'].aces if security_descriptor['Sacl']
                ],
                'Dacl': [
                    {
                        'User': get_formatted_sid(ace),
                        'Permissions': {
                            'PermissionsType': ace['TypeName'],
                            'PermissionsValue': calculate_permissions(ace['Ace']['Mask']['Mask']),
                            'PermissionsObjects': get_advanced_properties(ace),
                            'InheritedObjectType': get_inherited(ace)
                        }
                    }
                    for ace in security_descriptor['Dacl'].aces if security_descriptor['Dacl']
                ]
            }
        elif self.object_type == 'reg_key':
            security_info = [
                {
                    'User': get_formatted_sid(ace),
                    'Permissions': {
                        'PermissionsType': ace['TypeName'],
                        'PermissionsValue': calculate_permissions(ace['Ace']['Mask']['Mask']),
                        'InheritedObjectType': get_inherited(ace)
                    }
                }
                for ace in security_descriptor['Dacl'].aces if security_descriptor['Dacl']
            ]
        return security_info

    def process_containers(self, containers):
        result = {}
        for container in containers:
            security_info = self.ace_details(container)
            user_permissions = {}
            for dacl in security_info['Dacl']:
                user = dacl.get('User')
                if user not in self.new_well_known_sids.values():
                    user_permissions.setdefault(user, [])
                    user_permissions[user].append(
                        {
                            'PermissionsValue': dacl['Permissions']['PermissionsValue'],
                            'PermissionsObjects': dacl['Permissions']['PermissionsObjects'],
                            'InheritedObjectType': dacl['Permissions']['InheritedObjectType']
                        }
                    )
            
            container_permissions = []
            for user, permissions in user_permissions.items():
                permissions_translation = [{'user': user, 'permissions': DELEGATIONS_ACE.get(str(permissions), [str(permission) for permission in permissions])}]
                container_permissions.extend(permissions_translation)
            result[container['distinguishedName']] = container_permissions
        return result

    def process_regKeys(self, reg_key):
        reg_permissions = {}
        security_info = self.ace_details(reg_key)
        for permission in security_info:
            user = permission["User"]
            perm_value = permission["Permissions"]["PermissionsValue"]

            if user not in reg_permissions:
                reg_permissions[user] = permission
            else:
                if not perm_value:
                    reg_permissions[user]["Permissions"]["InheritedObjectType"] = "This key and subkeys"
                else:
                    reg_permissions[user]["Permissions"]["PermissionsValue"] = perm_value
        result = list(reg_permissions.values())
        return result