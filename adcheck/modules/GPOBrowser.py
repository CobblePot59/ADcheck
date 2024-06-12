import re
from os import makedirs


def smb_download(connection, path, dst):
    match = re.search(r'sysvol', path, re.IGNORECASE)
    if match:
        path = path.split(match.group(), 1)[1]
    files = connection.listPath('sysvol', f'{path}/*')
    for f in files:
        fname = f.get_longname()
        current = f'{path}/{fname}'
        dst_path = current.replace(path, dst)
        if fname not in ['.', '..']:
            if f.is_directory():
                makedirs(dst_path, exist_ok=True)
                smb_download(connection, current, dst_path)
            else:
                fh = open(dst_path, 'wb')
                connection.getFile('sysvol', current, fh.write)

def smb_get_attributes(connection, path, gpo_path_rights=None):
    if gpo_path_rights is None:
        gpo_path_rights = []
    tree_id = connection.connectTree('sysvol')
    match = re.search(r'sysvol', path, re.IGNORECASE)
    if match:
        path = path.split(match.group(), 1)[1]
    files = connection.listPath('sysvol', f'{path}/*')
    for f in files:
        fname = f.get_longname()
        current = f'{path}/{fname}'
        if fname not in ['.', '..']:
            if f.is_directory():
                pattern = re.compile(re.escape(path) + r'(\/\{[0-9A-Fa-f-]+\})')
                match = pattern.match(current)
                if match:
                    gpo_path_rights.append({'is_directory': True, 'is_parent': True, 'path': current, 'rights': f.get_attributes()})
                else:
                    gpo_path_rights.append({'is_directory': True, 'is_parent': False, 'path': current, 'rights': f.get_attributes()})
                smb_get_attributes(connection, current, gpo_path_rights)
            else:
                gpo_path_rights.append({'is_directory': False, 'is_parent': False, 'path': current, 'rights': f.get_attributes()})
    return gpo_path_rights