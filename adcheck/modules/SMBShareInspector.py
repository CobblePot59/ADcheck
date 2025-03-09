from adcheck.libs.DescribeSDDL import parse_SDDL
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
import json


RED = '\033[91m'
RESET = '\033[0m'

users_to_highlight = ["everyone", "anonymous", "authenticated user", "guest"]

async def handle_share(smb_url):
    try:
        smb_mgr = SMBConnectionFactory.from_url(smb_url)
        connection = smb_mgr.create_connection_newtarget(smb_mgr.get_target().get_hostname_or_ip())

        async with connection:
            _, err = await connection.login()
            if err is not None:
                raise err

            machine = SMBMachine(connection)
            async for obj, otype, err in machine.enum_all_recursively(depth=1, fetch_share_sd=True):
                if err:
                    print(f'Error : {err}')
                    continue

                if otype == 'share':
                    security_descriptor = obj.security_descriptor.to_sddl() if obj.security_descriptor else 'No SDDL'
                    json_sd = parse_SDDL(security_descriptor)

                    print(f'[+] Listing ACL for share: {obj.unc_path}')
                    
                    if "DACL" in json_sd:
                        print("[")

                        for ace in json_sd["DACL"]:
                            ace_json = json.dumps(ace, indent=4)
                            if any(user.lower() in ace['SID'].lower() for user in users_to_highlight):
                                print(f"{RED}{ace_json}{RESET},")
                            else:
                                print(f"{ace_json},")
                        
                        print("]")
    finally:
        await connection.disconnect()