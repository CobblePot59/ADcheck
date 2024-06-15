from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5 import scmr
from impacket.examples.secretsdump import RemoteOperations
from impacket.smbconnection import SMBConnection
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from adcheck.modules.MSaceCalc import SecurityDescriptorParser
from struct import unpack
import binascii
import json


class CustomRemoteOperations(RemoteOperations):
    def __init__(self, smbConnection, doKerberos):
        self.__smbConnection = smbConnection
        self.__doKerberos = doKerberos
        self.__rrp = None

    def getRRP(self):
        return self.__rrp

    def connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\winreg]')
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

class RegReader:
    def __init__(self, remoteHost, username, password, domain, nthash, keyName, subKey=False):
        self.__remoteHost = remoteHost
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__nthash = nthash
        self.__keyName = keyName
        self.__smbConnection = None
        self.__doKerberos = False
        self.__remoteOps = None
        self.__subkey = subKey
    
    def __strip_root_key(self, dce, keyName):
        try:
            rootKey = keyName.split('\\')[0].upper()
            subKey = '\\'.join(keyName.split('\\')[1:-1])
            Key = keyName.split('\\')[-1]
        except Exception:
            print(f'Error parsing keyName {keyName}')

        reg_key = {'HKLM': rrp.hOpenLocalMachine, 'HKCU': rrp.hOpenCurrentUser, 'HKU': rrp.hOpenUsers, 'HKCR': rrp.hOpenClassesRoot}
        ans = reg_key.get(rootKey, lambda e: print(f'Invalid root key {rootKey}'))(dce)
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
                self.__print_all_subkeys_and_entries(rpc, newKeyName, ans['phkResult'])
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
        return reg_entries

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteHost, self.__remoteHost)
        self.__smbConnection.login(self.__username, self.__password, self.__domain, nthash=self.__nthash)
        self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos)

        try:
            self.__remoteOps.enableRegistry()
        except Exception as e:
            # Cannot check RemoteRegistry status. Triggering start trough named pipe...
            self.__remoteOps  = CustomRemoteOperations(self.__smbConnection, self.__doKerberos)
            self.__remoteOps.connectWinReg()

    def run(self):
        self.connect()
        try:
            dce = self.__remoteOps.getRRP()
            hRootKey, subKey, Key = self.__strip_root_key(dce, self.__keyName)
            ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey)
            if self.__subkey:
                value = self.__print_all_subkeys_and_entries(dce, f'{subKey}\\', ans2['phkResult'])
                new_value = []
                for av in value:
                    for key, value in av.items():
                        subkey_strings = "{}\\{}\\{}".format(self.__keyName.split('\\')[0].upper(), key.split('\\', 1)[0], key.split('\\', 1)[1])
                        new_value.append({subkey_strings: value})
                return new_value
            else:
                value = rrp.hBaseRegQueryValue(dce, ans2['phkResult'], Key)
                return value[1]
        except Exception as e:
            return e

    def get_security_descriptor(self):
        self.connect()
        try:
            dce = self.__remoteOps.getRRP()
            hRootKey, subKey, Key = self.__strip_root_key(dce, self.__keyName)
            ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey)
            key_handle = ans2['phkResult']

            resp = rrp.hBaseRegGetKeySecurity(dce, key_handle, scmr.DACL_SECURITY_INFORMATION)
            security_descriptor = b''.join(resp['pRpcSecurityDescriptorOut']['lpSecurityDescriptor'])
            return security_descriptor
        except Exception as e:
            return e