from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from adcheck.modules.constants import WELL_KNOWN_SIDS, ENTRANCE_ACCESS_CONTROL, LAPS_PROPERTIES_UUID
import json
import base64

def get_encoded_attr(encoded_attr):
    decoded_attr = base64.b64decode(json.loads(encoded_attr.replace("'", "\""))['encoded'])
    return decoded_attr

def ace_details(NEW_WELL_KNOWN_SIDS, schema_objects, schema_attributes, extended_rights, all_entries, container):
    security_descriptor = SR_SECURITY_DESCRIPTOR()
    security_descriptor.fromString(get_encoded_attr(container['nTSecurityDescriptor']))

    def get_formatted_sid(ace):
        sid = ace['Ace']['Sid'].formatCanonical()
        formated_sid = WELL_KNOWN_SIDS.get(sid) \
            or NEW_WELL_KNOWN_SIDS.get(sid) \
            or (WELL_KNOWN_SIDS.get("S-1-5-5") if sid.startswith("S-1-5-5") else None) \
            or [entry['sAMAccountName'] for entry in all_entries if 'objectSid' in entry and sid == entry['objectSid']][0] \
            or sid
        return formated_sid
    
    def calculate_permissions(mask):
        if mask == ENTRANCE_ACCESS_CONTROL["Full control"]:
            permissions = "Full control"
        else:
            permissions = []
            for attribute, bitmask in ENTRANCE_ACCESS_CONTROL.items():
                if int(mask) & bitmask and attribute != "Full control":
                    permissions.append(attribute)
        return permissions

    def get_advanced_properties(ace):
        if ace['TypeName'] == 'ACCESS_ALLOWED_OBJECT_ACE' or ace['TypeName'] == 'ACCESS_DENIED_OBJECT_ACE':
            _uuid = ace['Ace']['ObjectType']
            _uuid_hex = str(_uuid.hex())
            _uuid_hex = "-".join([_uuid_hex[:8], _uuid_hex[8:12], _uuid_hex[12:16], _uuid_hex[16:20], _uuid_hex[20:]])
            rightsGuid = "{}{}{}{}-{}{}-{}{}-{}-{}".format(_uuid_hex[6:8], _uuid_hex[4:6], _uuid_hex[2:4], _uuid_hex[0:2], _uuid_hex[11:13], _uuid_hex[9:11], _uuid_hex[16:18], _uuid_hex[14:16], _uuid_hex[19:23], _uuid_hex[24:])
            advanced_properties = [schema_object['name'] for schema_object in schema_objects if str(get_encoded_attr(schema_object['schemaIDGUID'])) == str(_uuid)] \
                or [schema_attribute['name'] for schema_attribute in schema_attributes if str(get_encoded_attr(schema_attribute['schemaIDGUID'])) == str(_uuid)] \
                or [extended_right['displayName'] for extended_right in extended_rights if extended_right['rightsGuid'] == rightsGuid] \
                or [key for key, value in LAPS_PROPERTIES_UUID.items() if str(value) == str(_uuid)]
            return advanced_properties

    def get_inherited(ace):
        if ace['TypeName'] == 'ACCESS_ALLOWED_OBJECT_ACE' or ace['TypeName'] == 'ACCESS_DENIED_OBJECT_ACE':
            if len(ace['Ace']['InheritedObjectType'])>0:
                decendant = [schema_object['name'] for schema_object in schema_objects if str(get_encoded_attr(schema_object['schemaIDGUID'])) == str(ace['Ace']['InheritedObjectType'])]
                return decendant
    
    security_info = {
        'Object': container['distinguishedName'],
        'Owner': NEW_WELL_KNOWN_SIDS.get(security_descriptor['OwnerSid'].formatCanonical()),
        'GroupOwner': NEW_WELL_KNOWN_SIDS.get(security_descriptor['GroupSid'].formatCanonical()),
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
    return security_info