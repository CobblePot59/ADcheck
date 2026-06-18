from adcheck.modules.connection import ADClient
from adcheck.main import ADcheck, Options
from adcheck.modules.constants import CHECKLIST, ANSI
from adcheck.modules.report import ReportGenerator
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from importlib.metadata import version
import asyncio
import sys
import time


__version__ = version("ADcheck")

async def launch_all_methods(obj, is_admin=False, module=None, hashes=None, aes_key=None, debug=False):
    i = 0
    quiet = getattr(obj, 'quiet', False)
    await getattr(obj, 'get_policies')()

    excluded_methods = ['get_policies']
    if hashes or aes_key:
        excluded_methods += ['wmi_last_backup', 'wmi_last_update']

    CHECKLIST_EXEC = {}
    for categories in CHECKLIST.values():
        for category in categories:
            for section, modules in category.items():
                CHECKLIST_EXEC.setdefault(section, []).extend(modules)

    if module:
        try:
            if module == 'get_policies':
                pass
            else:
                await getattr(obj, module)()
        except Exception as e:
            if debug:
                print(f"{ANSI['yellow']}{module}: {e}{ANSI['reset']}")
            else:
                print(f"{ANSI['yellow']}{module}: error{ANSI['reset']}")
    else:
        for section, modules in CHECKLIST_EXEC.items():
            if not quiet:
                print(f"\n{ANSI['yellow']}{'=' * 20} {section} {'=' * 20}{ANSI['reset']}\n")
            for module in modules:
                method_name = module[0]
                if method_name and method_name not in excluded_methods:
                    if not is_admin and not hasattr(getattr(ADcheck, method_name), '__wrapped__') or is_admin:
                        i += 1
                        if not quiet:
                            print(f'{i} - ', end='')
                        try:
                            if debug and not quiet:
                                print(f"{method_name}")
                            await getattr(obj, method_name)()
                        except Exception as e:
                            if debug:
                                print(f"{ANSI['yellow']}{method_name}: {e}{ANSI['reset']}")
                            elif not quiet:
                                print(f"{ANSI['yellow']}{method_name}: error{ANSI['reset']}")

def parse_arguments():
    epilog = f"""
{ANSI['cyan']}Example of use:{ANSI['reset']}
  {ANSI['yellow']}adcheck -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1'{ANSI['reset']}
"""

    parser = ArgumentParser(
        description=f"{ANSI['cyan']}ADcheck - Active Directory Security Checker{ANSI['reset']}",
        epilog=epilog,
        formatter_class=RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--domain', help='Domain name of the target system.')
    parser.add_argument('-u', '--username', help='Username for authentication.')
    parser.add_argument('-p', '--password', help='Password for authentication.')
    parser.add_argument('-H', '--hashes', help='Hashes for authentication.')
    parser.add_argument('--aes', help='AES for authentication.')
    parser.add_argument('--hostname', help='Name of the Domain Controller.')
    parser.add_argument('--dc-ip', help='IP address of the Domain Controller.')
    parser.add_argument('-s', '--secure', action='store_true', help='Use SSL for secure communication.')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use kerberos instead of NTLM.')
    parser.add_argument('-L', '--list-modules', action='store_true', help=f"{ANSI['green']}List available modules.{ANSI['reset']}")
    parser.add_argument('-M', '--module', help='Module to use.')
    parser.add_argument('-o', '--output', choices=['html', 'md'], help='Generate report file in HTML or Markdown format.')
    parser.add_argument('-e', '--exploit', action='store_true', help='Show exploitation hints for supported modules.')
    parser.add_argument('-f', '--fix', action='store_true', help='Show fix advice under each failed check.')
    parser.add_argument('--summarize', action='store_true', help='Print only a prioritized summary (category, state, CVSS, exploit and fix)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity (show more detailed information).')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging.')
    parser.add_argument('--version', action='version', version=f'ADcheck v{__version__}')

    args = parser.parse_args()

    if args.list_modules:
        return args
    
    required_args = ['domain', 'username', 'dc_ip']
    missing = [arg for arg in required_args if not getattr(args, arg)]
    if missing:
        missing_flags = ', '.join([f'--{arg.replace("_", "-")}' for arg in missing])
        parser.error(f'the following arguments are required: {missing_flags}')
    
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

    loop = asyncio.get_running_loop()
    loop.set_exception_handler(
        lambda l, ctx: None if 'Task was destroyed but it is pending' in ctx.get('message', '')
        else l.default_exception_handler(ctx)
    )

    start_time = time.time()
    args = parse_arguments()

    if args.list_modules:
        for category, sections in CHECKLIST.items():
            if 'HIGH' in category:
                print(f"{ANSI['red']}{category}{ANSI['reset']}")
            else:
                print(f"{ANSI['cyan']}{category}{ANSI['reset']}")

            for section, modules in sections[0].items():
                print(f"    {ANSI['yellow']}{section}{ANSI['reset']}")
                for module in modules:
                    module_name, module_desc = module[0], module[1]
                    if not module_name:
                        print(f'        {module_name.ljust(34)} {module_desc}')
                    else:
                        print(f"        {ANSI['green']}[*]{ANSI['reset']} {ANSI['magenta']}{module_name.ljust(30)}{ANSI['reset']} {module_desc}")
            print()
        sys.exit(0)

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
    options.exploit = args.exploit
    options.verbose = args.verbose
    options.fix = args.fix
    options.quiet = args.summarize

    url = parse_url(domain, username, hashes, aes_key, password, hostname, dc_ip, options)

    protocol = 'LDAPS' if options.secure else 'LDAP'
    if options.kerberos:
        auth_method = 'Kerberos+AES' if aes_key else ('Kerberos+RC4' if hashes else 'Kerberos')
    else:
        auth_method = 'NTLM+Hash' if hashes else 'NTLM'
    target = hostname or dc_ip
    print(f"{ANSI['cyan']}Target{ANSI['reset']}    : {target} ({dc_ip})" if hostname else f"{ANSI['cyan']}Target{ANSI['reset']}    : {target}")
    print(f"{ANSI['cyan']}Domain{ANSI['reset']}    : {domain}")
    print(f"{ANSI['cyan']}Username{ANSI['reset']}  : {username}")
    print(f"{ANSI['cyan']}Protocol{ANSI['reset']}  : {protocol}")
    print(f"{ANSI['cyan']}Auth{ANSI['reset']}      : {auth_method}")
    print()

    ad_client = ADClient(domain=domain, url=url)
    try:
        await ad_client.connect()
    except (OSError, TimeoutError, asyncio.TimeoutError) as e:
        print(f"{ANSI['red']}Error: unable to reach the domain controller.{ANSI['reset']}")
        return
    except Exception as e:
        print(f"{ANSI['red']}Error: invalid credentials or authentication method.{ANSI['reset']}")
        return

    server_info = ad_client.msldap_client.get_server_info()
    if server_info:
        dc_domain_dn = server_info.get('defaultNamingContext', '').lower()
        if dc_domain_dn and dc_domain_dn != ad_client.base_dn.lower():
            print(f"{ANSI['red']}Error: domain '{domain}' does not match the DC's domain '{dc_domain_dn}'.{ANSI['reset']}")
            await ad_client.disconnect()
            return

    # Check if user is admin
    try:
        domain_sid = (await ad_client.msldap_client.get_ad_info())[0].objectSid
        admin_groups = ['S-1-5-32-544', f'{domain_sid}-512', f'{domain_sid}-519']
        try:
            user_groups = (await ad_client.msldap_client.get_user(username))[0].memberOf
            if isinstance(user_groups, str):
                user_groups = [(await ad_client.msldap_client.get_group_by_dn(user_groups))[0].objectSid]
            else:
                user_groups = [(await ad_client.msldap_client.get_group_by_dn(dn))[0].objectSid for dn in user_groups]
        except Exception as e:
            user_groups = [f'{domain_sid}-513']
    finally:
        await ad_client.disconnect()

    try:
        if any(user_group in admin_groups for user_group in user_groups):
            options.is_admin = True
            adcheck = ADcheck(domain, username, password, hashes, aes_key, hostname, dc_ip, url, options)
            await adcheck.connect()
            await launch_all_methods(adcheck, is_admin=True, module=module, hashes=hashes, aes_key=aes_key, debug=debug)
        else:
            adcheck = ADcheck(domain, username, password, hashes, aes_key, hostname, dc_ip, url, options)
            await adcheck.connect()
            await launch_all_methods(adcheck, module=module, hashes=hashes, aes_key=aes_key, debug=debug)

        report_generator = ReportGenerator(adcheck.report_results, domain, additional_tables=adcheck.report_tables)
        if args.summarize:
            report_generator.gen_cli_summary(summarize=True)
        report_path = None
        if args.output == 'html':
            report_path = report_generator.gen_html()
        elif args.output == 'md':
            report_path = report_generator.gen_markdown()
        if report_path:
            from pathlib import Path as _Path
            uri = _Path(report_path).as_uri()
            link = f"\033]8;;{uri}\033\\{report_path}\033]8;;\033\\"
            print(f"\n{ANSI['white']}Report saved :{ANSI['reset']} {link}")
    finally:
        await adcheck.disconnect()

    elapsed = time.time() - start_time
    print(f"\n{ANSI['white']}✓ Elapsed time : {elapsed:.2f}s{ANSI['reset']}")


def run_main():
    asyncio.run(main())

if __name__ == '__main__':
    run_main()