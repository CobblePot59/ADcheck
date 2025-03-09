from adcheck.core.__main__ import ADcheck, Options
from adcheck.modules.constants import CHECKLIST
from adcheck.modules.report import ReportGenerator
from msldap.commons.factory import LDAPConnectionFactory
from argparse import ArgumentParser
import asyncio
import sys


__version__ = "1.5.2"

async def launch_all_methods(obj, is_admin=False, module=None, hashes=None, aes_key=None, debug=False):
    i = 0
    await getattr(obj, 'get_policies')()

    excluded_methods = ['bloodhound_file']
    if hashes or aes_key:
        excluded_methods += ['wmi_last_backup', 'wmi_last_update']

    CHECKLIST_EXEC = {}
    for categories in CHECKLIST.values():
        for category in categories:
            for section, modules in category.items():
                CHECKLIST_EXEC.setdefault(section, []).extend(modules)

    if module:
        await getattr(obj, module)()
    else:
        for section, modules in CHECKLIST_EXEC.items():
            print(f"\n\033[33m{'=' * 20} {section} {'=' * 20}\033[0m\n")
            for module in modules:
                method_name = module[0]
                if method_name and method_name not in excluded_methods:
                    if not is_admin and not hasattr(getattr(ADcheck, method_name), '__wrapped__') or is_admin:
                        i += 1
                        print(method_name) if debug else None
                        print(f'{i} - ', end='')
                        await getattr(obj, method_name)()

def parse_arguments():
    parser = ArgumentParser(description='Process some arguments')
    parser.add_argument('-d', '--domain', required=True, help='Domain name of the target system.')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication.')
    parser.add_argument('-p', '--password', help='Password for authentication.')
    parser.add_argument('-H', '--hashes', help='Hashes for authentication.')
    parser.add_argument('--aes', help='AES for authentication.')
    parser.add_argument('--hostname', help='Name of the Domain Controller.')
    parser.add_argument('--dc-ip', required=True, help='IP address of the Domain Controller.')
    parser.add_argument('-s', '--secure', action='store_true', help='Use SSL for secure communication.')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use kerberos instead of NTLM.')
    parser.add_argument('-L', '--list-modules', action='store_true', help='List available modules.')
    parser.add_argument('-M', '--module', help='Module to use.')
    parser.add_argument('-o', '--output', action='store_true', help='Generate HTML report file.')
    parser.add_argument('--debug', action='store_true', help='Print method name.')
    parser.add_argument('--version', action='version', version=f'ADcheck v{__version__}')
    args = parser.parse_args()
    return args

def parse_url(domain, username, hashes, aes_key, password, hostname, dc_ip, options):
    protocol = 'ldaps' if options.secure else 'ldap'
    auth = 'kerberos-password' if options.kerberos and not aes_key and not hashes else 'ntlm-password'
    subdomain = domain.split('.')[0]

    if hashes:
        password, auth = hashes.split(':')[1], 'kerberos-rc4' if options.kerberos else 'ntlm-nt'
    if aes_key:
        password, auth = aes_key, 'kerberos-aes'
    return f"{protocol}+{auth}://{subdomain}\\{username}:{password}@{hostname or dc_ip}/?dc={dc_ip}"

async def main():
    from getpass import getpass

    args = parse_arguments()
    domain = args.domain
    username = args.username
    hashes = args.hashes
    aes_key = args.aes
    password = args.password or hashes or aes_key or getpass('Password :')
    hostname = args.hostname
    dc_ip = args.dc_ip
    
    module = args.module
    debug = args.debug

    options = Options()
    options.secure = args.secure
    options.kerberos = args.kerberos
    options.output = args.output

    if args.list_modules:
        for category, sections in CHECKLIST.items():
            print(category)
            for section, modules in sections[0].items():
                print(f'    {section}')
                for module in modules:
                    module_name, module_desc = module[0], module[1]
                    if not module_name:
                        print(f'        {module_name.ljust(34)} {module_desc}')
                    else:
                        print(f'        [*] {module_name.ljust(30)} {module_desc}')
            print()
        sys.exit(0)

    url = parse_url(domain, username, hashes, aes_key, password, hostname, dc_ip, options)
    ad_client = LDAPConnectionFactory.from_url(url).get_client()
    await ad_client.connect()

    # Check if user is admin
    try:
        domain_sid = (await ad_client.get_ad_info())[0].objectSid
        admin_groups = ['S-1-5-32-544', f'{domain_sid}-512', f'{domain_sid}-519']
        user_groups = (await ad_client.get_user(username))[0].memberOf
        if not user_groups:
            user_groups = [f'{domain_sid}-513']
        elif isinstance(user_groups, str):
            user_groups = [(await ad_client.get_group_by_dn(user_groups))[0].objectSid]
        else:
            user_groups = [(await ad_client.get_group_by_dn(dn))[0].objectSid for dn in user_groups]
    finally:
        await ad_client.disconnect()

    if any(user_group in admin_groups for user_group in user_groups):
        options.is_admin = True
        adcheck = ADcheck(domain, username, password, hashes, aes_key, hostname, dc_ip, url, options)
        await adcheck.connect()
        await launch_all_methods(adcheck, is_admin=True, module=module, hashes=hashes, aes_key=aes_key, debug=debug)
    else:
        adcheck = ADcheck(domain, username, password, hashes, aes_key, hostname, dc_ip, url, options)
        await adcheck.connect()
        await launch_all_methods(adcheck, module=module, hashes=hashes, aes_key=aes_key, debug=debug)

    if args.output:
        report_generator = ReportGenerator(adcheck.report_results)
        report_generator.gen_html()

def run_main():
    asyncio.run(main())

if __name__ == '__main__':
    run_main()