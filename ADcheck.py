from adcheck.core.__main__ import ADcheck, Options
from adcheck.modules.constants import CHECKLIST
from argparse import ArgumentParser
import sys
import re


def launch_all_methods(obj, is_admin=False, debug=False):
    i = 0
    getattr(obj, 'get_policies')()
    if module:
        getattr(obj, f'{module}')()
    else:
        excluded_methods = ['connect', 'update_entries', 'reg_client', 'wmi_client', 'pprint', 'ntds_dump', 'get_policies', 'bloodhound_file']
        if hashes:
            excluded_methods = ['connect', 'update_entries', 'reg_client', 'wmi_client', 'pprint', 'ntds_dump', 'get_policies', 'bloodhound_file', 'wmi_last_backup', 'wmi_last_update']

        methods = [method for method in dir(obj) if callable(getattr(obj, method)) and not method.startswith('__')]
        for method_name in methods:
            print(method_name) if debug else None
            if method_name not in excluded_methods:
                if not is_admin and not hasattr(getattr(ADcheck, method_name), '__wrapped__'):
                    i += 1
                    print(f'{i} - ', end='')
                    getattr(obj, method_name)()
                elif is_admin:
                    i += 1
                    print(f'{i} - ', end='')
                    getattr(obj, method_name)()

def parse_arguments():
    parser = ArgumentParser(description='Process some arguments')
    parser.add_argument('-d', '--domain', required=True, help='Domain name of the target system.')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication.')
    parser.add_argument('-p', '--password', help='Password for authentication.')
    parser.add_argument('-H', '--hashes', help='Hashes for authentication.')
    parser.add_argument('--dc-ip', required=True, help='IP address of the Domain Controller.')
    parser.add_argument('-s', '--secure', action='store_true', help='Use SSL for secure communication.')
    parser.add_argument('-L', '--list-modules', action='store_true', help='List available modules.')
    parser.add_argument('-M', '--module', help='Module to use.')
    parser.add_argument('-o', '--output', action='store_true', help='Generate HTML report file.')
    parser.add_argument('--debug', action='store_true', help='Print method name.')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    from getpass import getpass

    args = parse_arguments()
    domain = args.domain
    username = args.username
    hashes = args.hashes
    password = args.password or hashes or getpass('Password :')
    dc_ip = args.dc_ip
    module = args.module
    debug = args.debug

    if args.list_modules:
        for category, modules in CHECKLIST.items():
            print(category)
            for module_name, module_desc in modules:
                if not module_name:
                    print(f'{module_name.ljust(34)} {module_desc}')
                else:
                    print(f'[*] {module_name.ljust(30)} {module_desc}')
        sys.exit(0)

    options = Options()
    options.secure = args.secure
    options.output = args.output
    adcheck = ADcheck(domain, username, password, hashes, dc_ip, options)

    is_admin = False
    admin_groups = ['S-1-5-32-544', f'{adcheck.domain_sid}512', f'{adcheck.domain_sid}519']
    user_groups = adcheck.ad_client.get_memberOf(username)
    if not user_groups:
        user_groups = [f'{adcheck.domain_sid}513']
    elif isinstance(user_groups, str):
        user_groups = [adcheck.ad_client.get_ADobject(re.search(r'CN=([^,]+)', user_groups).group(1))['objectSid']]
    else:
        user_groups = [adcheck.ad_client.get_ADobject(re.search(r'CN=([^,]+)', dn).group(1))['objectSid'] for dn in user_groups] 

    for admin_group in admin_groups:
        for user_group in user_groups:
            if user_group in admin_group:
                is_admin = True
                break

    if is_admin:
        options.is_admin = True
        adcheck = ADcheck(domain, username, password, hashes, dc_ip, options)
        with open('report.html', 'w') as report:
            report.write('<html><body><pre>\n')
        launch_all_methods(adcheck, is_admin=True, debug=debug)
        with open('report.html', 'a') as report:
            report.write('</pre></body></html>')
    else:
        launch_all_methods(adcheck, debug=debug)