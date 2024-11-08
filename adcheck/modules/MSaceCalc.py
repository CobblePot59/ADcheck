from adcheck.libs.impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from modules.constants import ENTRANCE_ACCESS_CONTROL, REGISTRY_ACCESS_RIGHT, LAPS_PROPERTIES_UUID, REGISTRY_ACCESS_INHERITED, DELEGATIONS_ACE
import uuid


class SecurityDescriptorParser:
    def __init__(self, new_well_known_sids, schema_objects, schema_attributes, extended_rights, all_entries, object_type):
        self.new_well_known_sids = new_well_known_sids
        self.schema_objects = schema_objects
        self.schema_attributes = schema_attributes
        self.extended_rights = extended_rights
        self.all_entries = all_entries
        self.object_type = object_type

    def ace_details(self, _object):
        if self.object_type == 'container':
            security_descriptor = SR_SECURITY_DESCRIPTOR()
            security_descriptor.fromString(_object.get('nTSecurityDescriptor'))
        elif self.object_type == 'reg_key':
            security_descriptor = SR_SECURITY_DESCRIPTOR(_object)

        def get_formatted_sid(ace):
            sid = ace['Ace']['Sid'].formatCanonical()
            formatted_sid = self.new_well_known_sids.get(sid) \
                or (self.new_well_known_sids.get('S-1-5-5') if sid.startswith('S-1-5-5') else None) \
                or next((entry.get('sAMAccountName') for entry in self.all_entries if 'objectSid' in entry and sid == entry.get('objectSid')), None) \
                or sid
            return formatted_sid

        def calculate_permissions(mask):
            if self.object_type == 'container':
                ACCESS_CONTROL = ENTRANCE_ACCESS_CONTROL
            elif self.object_type == 'reg_key':
                ACCESS_CONTROL = REGISTRY_ACCESS_RIGHT
            else:
                return []

            if mask == ACCESS_CONTROL.get('Full Control'):
                permissions = 'Full Control'
            elif self.object_type == 'reg_key' and mask == ACCESS_CONTROL.get('Read'):
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
                _uuid.hex()
                _guid = str(uuid.UUID(bytes_le=_uuid)) if _uuid else None
                advanced_properties = [schema_object.get('name') for schema_object in self.schema_objects if schema_object.get('schemaIDGUID') == _guid] \
                    or [schema_attribute.get('name') for schema_attribute in self.schema_attributes if schema_attribute.get('schemaIDGUID') == _guid] \
                    or [extended_right.get('displayName') for extended_right in self.extended_rights if extended_right.get('rightsGuid') == _guid] \
                    or [key for key, value in LAPS_PROPERTIES_UUID.items() if str(value) == str(_uuid)]
                return advanced_properties

        def get_inherited(ace):
            if self.object_type == 'container':
                if ace['TypeName'] == 'ACCESS_ALLOWED_OBJECT_ACE' or ace['TypeName'] == 'ACCESS_DENIED_OBJECT_ACE':
                    if len(ace['Ace']['InheritedObjectType']) > 0:
                        _uuid = ace['Ace']['InheritedObjectType']
                        _guid = str(uuid.UUID(bytes_le=_uuid)) if _uuid else None
                        descendant = [schema_object.get('name') for schema_object in self.schema_objects if schema_object.get('schemaIDGUID') == _guid]
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
            for dacl in security_info.get('Dacl'):
                user = dacl.get('User')
                if user not in self.new_well_known_sids.values():
                    user_permissions.setdefault(user, [])
                    user_permissions[user].append(
                        {
                            'PermissionsValue': dacl.get('Permissions').get('PermissionsValue'),
                            'PermissionsObjects': dacl.get('Permissions').get('PermissionsObjects'),
                            'InheritedObjectType': dacl.get('Permissions').get('InheritedObjectType')
                        }
                    )
            
            container_permissions = []
            for user, permissions in user_permissions.items():
                delegations_ace = list({description for delegation, description in DELEGATIONS_ACE
                                    for np in permissions
                                    for nd in delegation
                                    if (np.get('PermissionsValue') == nd.get('PermissionsValue') and
                                        np.get('PermissionsObjects') == nd.get('PermissionsObjects') and
                                        np.get('InheritedObjectType') == nd.get('InheritedObjectType'))})
                permissions_translation = [{'user': user, 'permissions': delegations_ace}]
                container_permissions.extend(permissions_translation)
            result[container.get('distinguishedName')] = container_permissions
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