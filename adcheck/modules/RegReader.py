from libs.impacket.dcerpc.v5 import transport, rrp, scmr
from libs.impacket.smbconnection import SMBConnection
from libs.impacket.system_errors import ERROR_NO_MORE_ITEMS
from struct import unpack
import binascii


class RemoteOperations:
    def __init__(self, smb_client, do_kerberos):
        self.smb_client = smb_client
        self.do_kerberos = do_kerberos
        self.rrp = None

    def connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(rf'ncacn_np:445[\pipe\winreg]')
        rpc.set_smb_connection(self.smb_client)
        self.rrp = rpc.get_dce_rpc()
        self.rrp.connect()
        self.rrp.bind(rrp.MSRPC_UUID_RRP)

class RegReader:
    def __init__(self, domain, username, password, nthash, aes_key, hostname, dc_ip, do_kerberos, keyName, subKey=False):
        self.domain = domain
        self.username = username
        self.password = password
        self.nthash = nthash
        self.aes_key = aes_key
        self.hostname = hostname
        self.dc_ip = dc_ip
        self.do_kerberos = do_kerberos
        self.smb_client = None
        self.remoteOps = None
        self.keyName = keyName
        self.subKey = subKey
    
    def __strip_root_key(self, rpc, keyName, subKey_flag=False):
        try:
            rootKey = keyName.split('\\')[0].upper()
            subKey = '\\'.join(keyName.split('\\')[1:]) if subKey_flag else '\\'.join(keyName.split('\\')[1:-1])
            Key = keyName.split('\\')[-1]
        except Exception:
            print(f'Error parsing keyName {keyName}')

        reg_key = {'HKLM': rrp.hOpenLocalMachine, 'HKCU': rrp.hOpenCurrentUser, 'HKU': rrp.hOpenUsers, 'HKCR': rrp.hOpenClassesRoot}
        ans = reg_key.get(rootKey, lambda e: print(f'Invalid root key {rootKey}'))(rpc)
        hRootKey = ans['phKey']

        return hRootKey, subKey, Key

    def __parse_lp_data(self, valueType, valueData):
        type_operations = {
            rrp.REG_SZ: lambda data: 'NULL' if isinstance(data, int) else data.decode('utf-16le')[:-1],
            rrp.REG_EXPAND_SZ: lambda data: 'NULL' if isinstance(data, int) else data.decode('utf-16le')[:-1],
            rrp.REG_BINARY: lambda data: binascii.hexlify(data),
            rrp.REG_DWORD: lambda data: f"0x{unpack('<L', data)[0]}",
            rrp.REG_QWORD: lambda data: f"0x{unpack('<Q', data)[0]}",
            rrp.REG_NONE: lambda data: binascii.hexlify(data) if len(data) > 1 else 'NULL',
            rrp.REG_MULTI_SZ: lambda data: data.decode('utf-16le')[:-2]
        }

        default_operation = lambda data: hexdump(data)
        operation = type_operations.get(valueType, default_operation)

        return operation(valueData)

    def __print_key_values(self, rpc, keyHandler):
        i = 0
        reg_values = []
        while True:
            try:
                ans4 = rrp.hBaseRegEnumValue(rpc, keyHandler, i)
                lp_value_name = ans4['lpValueNameOut'][:-1]
                if len(lp_value_name) == 0:
                    lp_value_name = '(Default)'
                reg_values.append({lp_value_name: self.__parse_lp_data(ans4['lpType'], b''.join(ans4['lpData']))})
                i += 1
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
        return reg_values

    def __print_all_subkeys_and_entries(self, rpc, keyName, keyHandler):
        index = 0
        reg_entries = []
        while True:
            try:
                subkey = rrp.hBaseRegEnumKey(rpc, keyHandler, index)
                index += 1
                ans = rrp.hBaseRegOpenKey(rpc, keyHandler, subkey['lpNameOut'])
                newKeyName = f"{keyName}{subkey['lpNameOut'][:-1]}\\"
                reg_entries.append({newKeyName: self.__print_key_values(rpc, ans['phkResult'])})
                self.__print_all_subkeys_and_entries(rpc=rpc, keyName=newKeyName, keyHandler=ans['phkResult'])
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
        return reg_entries

    def connect(self):
        if self.do_kerberos:
            self.smb_client = SMBConnection(self.hostname, self.dc_ip)
            self.smb_client.kerberosLogin(domain=self.domain, user=self.username, password=self.password, nthash=self.nthash, aesKey=self.aes_key, kdcHost=self.hostname, useCache=False)
        else:
            self.smb_client = SMBConnection(self.dc_ip, self.dc_ip)
            self.smb_client.login(domain=self.domain, user=self.username, password=self.password, nthash=self.nthash)
        self.remoteOps = RemoteOperations(smb_client=self.smb_client, do_kerberos=self.do_kerberos)
        self.remoteOps.connectWinReg()

    def run(self):
        self.connect()
        try:
            rpc = self.remoteOps.rrp
            hRootKey, subKey, Key = self.__strip_root_key(rpc=rpc, keyName=self.keyName)
            ans2 = rrp.hBaseRegOpenKey(rpc, hRootKey, subKey)
            if self.subKey:
                value = self.__print_all_subkeys_and_entries(rpc=rpc, keyName=f'{subKey}\\', keyHandler=ans2['phkResult'])
                new_value = []
                for av in value:
                    for key, value in av.items():
                        subkey_strings = "{}\\{}\\{}".format(self.keyName.split('\\')[0].upper(), key.split('\\', 1)[0], key.split('\\', 1)[1])
                        new_value.append({subkey_strings: value})
                return new_value
            else:
                value = rrp.hBaseRegQueryValue(rpc, ans2['phkResult'], Key)
                return value[1]
        except Exception as e:
            return e

    def get_security_descriptor(self):
        self.connect()
        try:
            rpc = self.remoteOps.rrp
            rrp.hOpenLocalMachine(rpc)
            hRootKey, subKey, Key = self.__strip_root_key(rpc=rpc, keyName=self.keyName, subKey_flag=True)
            ans2 = rrp.hBaseRegOpenKey(rpc, hRootKey, subKey)
            key_handle = ans2['phkResult']

            resp = rrp.hBaseRegGetKeySecurity(rpc, key_handle, scmr.DACL_SECURITY_INFORMATION)
            security_descriptor = b''.join(resp['pRpcSecurityDescriptorOut']['lpSecurityDescriptor'])
            return security_descriptor
        except Exception as e:
            return e