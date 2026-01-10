from msldap.commons.factory import LDAPConnectionFactory
from msldap.connection import MSLDAPClientConnection
from msldap.wintypes.dnsp.structures.dnsrecord import DNS_RECORD

class ADClient:
    def __init__(self, domain, url):
        self.domain = domain
        self.base_dn = ",".join([f"DC={part}" for part in domain.split('.')])
        self.url = url
        self.msldap_conn = None
        self.msldap_client = None
        self.msldap_client_conn_err = None

    async def connect(self, cb_data=None):
        self.msldap_conn = LDAPConnectionFactory.from_url(self.url).get_connection()
        await self.msldap_conn.connect()
        await self.msldap_conn.bind()

        self.msldap_client = LDAPConnectionFactory.from_url(self.url).get_client()

        if cb_data:
            msldap_client_conn = MSLDAPClientConnection(self.msldap_client.target, self.msldap_client.creds)
            await msldap_client_conn.connect()
            msldap_client_conn.cb_data = cb_data
            _, self.msldap_client_conn_err = await msldap_client_conn.bind()

        await self.msldap_client.connect()
        return self.msldap_client

    async def disconnect(self):
        if self.msldap_conn:
            await self.msldap_conn.disconnect()
        if self.msldap_client:
            await self.msldap_client.disconnect()

    async def get_ADobjects(self, custom_base_dn=None, custom_filter=None, custom_attributes=None):
        ad_objects = self.msldap_conn.pagedsearch(
            base=custom_base_dn or self.base_dn,
            query=custom_filter or '(objectClass=*)',
            attributes=custom_attributes or [b'*']
        )

        ad_object = [ad_object.get('attributes') async for ad_object, e in ad_objects]
        return ad_object

    async def add_DNSentry(self, domain, hostname, ip):
        record = DNS_RECORD.create_A(ip, serial=1, ttlseconds=3600)
        dns_root = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{self.base_dn}"
        record_dn = f'DC={hostname},{dns_root}'
        
        attributes = {
            'objectClass': ['top', 'dnsNode'],
            'dnsRecord': [record.to_bytes()],
            'dNSTombstoned': False,
            'name': hostname
        }
    
        return await self.msldap_conn.add(record_dn, attributes)

    async def del_DNSentry(self, domain, hostname):
        dns_root = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{self.base_dn}"
        record_dn = f'DC={hostname},{dns_root}'
        return await self.msldap_conn.delete(record_dn)


from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.directory import SMBDirectory
import os


class AioSMBClient:
    def __init__(self, smb_url):
        self.smb_url = smb_url
        self.smbconn = None
        self.smbmachine = None
        
    async def connect(self):
        smb_mgr = SMBConnectionFactory.from_url(self.smb_url)
        self.smbconn = smb_mgr.get_connection()
        
        _, err = await self.smbconn.login()
        if err:
            raise err

        self.smbmachine = SMBMachine(self.smbconn)

    async def disconnect(self):
        if self.smbconn:
            await self.smbconn.disconnect()

    async def read_file(self, unc_path):
        if not self.smbconn:
            raise Exception("SMB connection is not established.")

        smbfile = SMBFile.from_uncpath(unc_path)
        _, err = await smbfile.open(self.smbconn)
        if err:
            raise err

        content = b''
        async for data, err in smbfile.read_chunked():
            if err:
                raise err
            if data is None:
                break
            content += data

        return content.decode(errors='replace')

    async def download_file(self, unc_path, local_path):
        if not self.smbconn:
            raise Exception("SMB connection is not established.")

        smbfile = SMBFile.from_uncpath(unc_path)
        _, err = await smbfile.open(self.smbconn)
        if err:
            raise err

        with open(local_path, 'wb') as outfile:
            async for data, err in smbfile.read_chunked():
                if err:
                    raise err
                if data is None:
                    break
                outfile.write(data)

    async def download_tree(self, unc_path, local_dir):
        if not self.smbconn:
            raise Exception("SMB connection is not established.")

        smbdir = SMBDirectory.from_uncpath(unc_path)

        async for obj, otype, err in smbdir.list_r(self.smbconn, depth=-1):
            if err or otype != 'file':
                continue

            if obj.unc_path.lower().startswith(unc_path.lower()):
                relpath = obj.unc_path[len(unc_path):].lstrip("\\/")
            else:
                relpath = obj.name

            local_path = os.path.join(local_dir, relpath.replace("\\", os.sep))
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            await self.download_file(obj.unc_path, local_path)

    async def security_descriptor(self, unc_path):
        if not self.smbconn:
            raise Exception("SMB connection is not established.")

        try:
            smbfile = SMBFile.from_uncpath(unc_path)
            sd, err = await smbfile.get_security_descriptor(self.smbconn)
            if err:
                raise Exception("Not a file")
        except Exception as e:
            if str(e) == "Not a file":
                smbdir = SMBDirectory.from_uncpath(unc_path)
                sd, err = await smbdir.get_security_descriptor(self.smbconn)
        if sd:
            return sd
    
    async def list_tree_with_sd(self, unc_path):
        if not self.smbconn:
            raise Exception("SMB connection is not established.")

        tree = {}
        smbdir = SMBDirectory.from_uncpath(unc_path)

        async for obj, otype, err in smbdir.list_r(self.smbconn, depth=-1):
            if err:
                continue

            try:
                sd = await self.security_descriptor(obj.unc_path)
                tree[obj.unc_path] = sd
            except Exception:
                continue

        return tree


from aiosmb.dcerpc.v5.common.service import ServiceStatus
from aiosmb.dcerpc.v5 import scmr
import logging
import asyncio

logging.getLogger("aiosmb").setLevel(logging.WARNING)

class SMBRegClient:
    def __init__(self, smb_client):
        self.smb_client = smb_client
        self.reg_api = None

    async def connect(self):
        try: 
            status, err = await self.smb_client.smbmachine.check_service_status("RemoteRegistry")
            if err:
                raise Exception(f"RemoteRegistry status error: {err}")
            
            if status != ServiceStatus.RUNNING:
                _, err = await self.smb_client.smbmachine.enable_service("RemoteRegistry")
                if err:
                    raise Exception(f"Enable RemoteRegistry error: {err}")
            
            for attempt in range(5):
                await asyncio.sleep(1)
                self.reg_api, err = await self.smb_client.smbmachine.get_regapi()
                if not err:
                    break
            else:
                raise Exception(f"Get RegAPI error after retry: {err}")
        except Exception:
            pass

    async def disconnect(self):
        await self.smb_client.disconnect()

    async def _open(self, regpath):
        hkey, err = await self.reg_api.OpenRegPath(regpath)
        if "The system cannot find the file specified." in str(err):
            return "OpenRegPath is None"
        elif err:
            raise Exception(f"OpenRegPath error: {err}")
        return hkey

    async def read_value(self, fullpath, default_value=None):
        regpath, name = fullpath.rsplit('\\', 1)
        hkey = await self._open(regpath)
        _, value, err = await self.reg_api.QueryValue(hkey, name)
        if "OpenRegPath is None" in str(err):
            return None
        elif "The system cannot find the file specified." in str(err):
            return default_value or None
        elif err:
            raise Exception(f"QueryValue error: {err}")
        return value

    async def enum_values(self, regpath):
        hkey = await self._open(regpath)
        results, i = [], 0
        while True:
            val = await self.reg_api.EnumValue(hkey, i)
            if val[3]: break
            results.append(val[:3])
            i += 1
        return results

    async def enum_keys(self, regpath):
        hkey = await self._open(regpath)
        results, i = [], 0
        while True:
            subkey, err = await self.reg_api.EnumKey(hkey, i)
            if err: break
            results.append(subkey)
            i += 1
        return results
    
    async def check_values(self, hives, any_match=False):
        async def check_one(hive_dict):
            for fullpath, expected_value in hive_dict.items():
                actual_value = await self.read_value(fullpath)
                if actual_value != expected_value:
                    return False
            return True

        if isinstance(hives, dict):
            return await check_one(hives)
        elif isinstance(hives, list):
            results = [await check_one(d) for d in hives]
            return any(results) if any_match else all(results)
        else:
            raise ValueError("hives must be a dict or a list of dicts")

    async def security_descriptor(self, fullpath, as_sddl=False):
        try:
            hkey = await self._open(fullpath)
            if hkey == "OpenRegPath is None":
                return None

            sd, err = await self.reg_api.GetKeySecurity(hkey, (scmr.OWNER_SECURITY_INFORMATION | scmr.GROUP_SECURITY_INFORMATION | scmr.DACL_SECURITY_INFORMATION))
            if err:
                raise Exception(f"GetKeySecurity error: {err}")

            sd_bin = b''.join(sd) if isinstance(sd, list) else sd
            if as_sddl:
                return sd_bin.to_sddl()
            return sd_bin

        except Exception as e:
            return e
        

from aiowmi.connection import Connection
from aiowmi.query import Query


class WMIquery():
    def __init__(self, remoteHost, username, password, domain, query, namespace):
        self.__remoteHost = remoteHost
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__query = query
        self.__namespace = namespace
        self.__wmiConnection = None

    async def connect(self):
        self.__wmiConnection = Connection(self.__remoteHost, self.__username, self.__password, domain=self.__domain)
        await self.__wmiConnection.connect()

    async def run(self):
        await self.connect()
 
        query = Query(self.__query, self.__namespace)
        service = await self.__wmiConnection.negotiate_ntlm()

        results = []
        async with query.context(self.__wmiConnection, service) as qc:
            async for props in qc.results():
                dict_props = {}
                for name, prop in props.items():
                    dict_props[name] = prop.value
                results.append(dict_props)
        return results