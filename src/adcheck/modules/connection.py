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

    async def connect(self, cb_data=None, disable_signing=False):
        self.msldap_conn = LDAPConnectionFactory.from_url(self.url).get_connection()
        _, err = await self.msldap_conn.connect()
        if err is not None:
            raise err
        _, err = await self.msldap_conn.bind()
        if err is not None:
            raise err

        self.msldap_client = LDAPConnectionFactory.from_url(self.url).get_client()

        if cb_data:
            msldap_client_conn = MSLDAPClientConnection(self.msldap_client.target, self.msldap_client.creds)
            try:
                await msldap_client_conn.connect()
                msldap_client_conn.cb_data = cb_data
                _, self.msldap_client_conn_err = await msldap_client_conn.bind()
            finally:
                await msldap_client_conn.disconnect()

        if disable_signing:
            msldap_client_conn = MSLDAPClientConnection(self.msldap_client.target, self.msldap_client.creds)
            msldap_client_conn._disable_signing = True
            try:
                await msldap_client_conn.connect()
                _, self.msldap_client_signing_err = await msldap_client_conn.bind()
            finally:
                await msldap_client_conn.disconnect()

        _, err = await self.msldap_client.connect()
        if err is not None:
            raise err
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


import asyncio
import os
from base64 import b64decode
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import UUID

try:
    from src.adws import ADWSConnect, KerberosAuth, NTLMAuth
    from src.soap_templates import NAMESPACES as ADWS_NAMESPACES
    from src.ad_dns_manager_adws import add_dns_record_adws, remove_dns_record_adws, get_rootdse_contexts
    from winacl.dtyp.sid import SID
    _ADWS_AVAILABLE = True
    _ADWS_IMPORT_ERROR = None
except ImportError as _e:
    _ADWS_AVAILABLE = False
    _ADWS_IMPORT_ERROR = _e


# ADWS returns every attribute as XML text (base64 for binary syntaxes); msldap returns
# richly-typed Python values (datetime, int, canonical SID strings, raw bytes for security
# descriptors, ...) that the rest of ADcheck relies on. The helpers below recreate that
# shape from the ADWS XML so both backends are interchangeable from main.py's point of view.
_ADWS_XSI_TYPE = '{http://www.w3.org/2001/XMLSchema-instance}type'
_ADWS_FILETIME_ATTRS = {
    'accountExpires', 'lastLogoff', 'badPasswordTime', 'lastLogon',
    'pwdLastSet', 'lastLogonTimestamp', 'lockoutTime',
}
_ADWS_ALWAYS_LIST_ATTRS = {
    'memberOf', 'servicePrincipalName', 'msDS-AllowedToDelegateTo',
    'msDS-PSOAppliesTo', 'altSecurityIdentities',
}
_ADWS_INT_SYNTAXES = {'Integer', 'Enumeration', 'LargeInteger'}


def _adws_coerce_value(attr_name, syntax, value_elem):
    text = value_elem.text
    if text is None:
        return None
    xsi_type = value_elem.attrib.get(_ADWS_XSI_TYPE)

    if xsi_type == 'xsd:base64Binary':
        raw = b64decode(text)
        if syntax == 'SidString' or attr_name == 'objectSid':
            return str(SID.from_bytes(raw))
        if attr_name == 'objectGUID':
            return str(UUID(bytes_le=raw)).upper()
        return raw

    if xsi_type == 'xsd:boolean':
        return text.strip().lower() == 'true'

    if attr_name in _ADWS_FILETIME_ATTRS:
        ticks = int(text)
        if ticks <= 0 or ticks >= 0x7FFFFFFFFFFFFFFF:
            return datetime(1601, 1, 1, tzinfo=timezone.utc)
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks / 10)

    if syntax in _ADWS_INT_SYNTAXES:
        return int(text)

    return text


def _adws_parse_items(et, pull_client):
    objects = []
    for item in pull_client._iter_response_objects(et):
        obj = {}
        for part in list(item):
            values = part.findall('./ad:value', namespaces=ADWS_NAMESPACES)
            if not values:
                continue
            attr_name = pull_client._get_tag_name(part)
            syntax = part.attrib.get('LdapSyntax')
            coerced = [_adws_coerce_value(attr_name, syntax, value) for value in values]
            obj[attr_name] = coerced if (len(coerced) > 1 or attr_name in _ADWS_ALWAYS_LIST_ATTRS) else coerced[0]
        if obj:
            objects.append(obj)
    return objects


class _ADWSObject:
    """Attribute-style accessor mirroring the small objects msldap returns
    (get_ADobjects() itself returns plain dicts on both backends)."""

    def __init__(self, attrs):
        self._attrs = attrs

    def __getattr__(self, name):
        return self._attrs.get(name)


class _MsldapClient:
    """Mimics the subset of msldap's client API, backed by ADWS queries through
    the owning ADWSClient's get_ADobjects()."""

    def __init__(self, adws_client):
        self._adws = adws_client

    def get_server_info(self):
        return self._adws._server_info

    async def _first(self, **kwargs):
        try:
            results = await self._adws.get_ADobjects(**kwargs)
        except Exception as e:
            return (None, e)
        return (_ADWSObject(results[0]), None) if results else (None, None)

    async def get_ad_info(self):
        return await self._first(custom_filter='(objectClass=domain)', custom_attributes=['objectSid'])

    async def get_dn_for_objectsid(self, sid):
        obj, err = await self._first(custom_filter=f'(objectSid={sid})', custom_attributes=['distinguishedName'])
        return (obj.distinguishedName if obj else None, err)

    async def get_user_by_dn(self, dn):
        return await self._first(custom_base_dn=dn, custom_filter='(objectClass=*)')

    async def get_group_by_dn(self, dn):
        return await self._first(custom_base_dn=dn, custom_filter='(objectClass=*)')

    async def get_user(self, username):
        return await self._first(custom_filter=f'(sAMAccountName={username})')

    async def get_group_members(self, group_dn):
        obj, err = await self._first(custom_base_dn=group_dn, custom_filter='(objectClass=*)', custom_attributes=['member'])
        if err or not obj or not obj.member:
            return
        for member_dn in ([obj.member] if isinstance(obj.member, str) else obj.member):
            yield await self._first(custom_base_dn=member_dn, custom_filter='(objectClass=*)', custom_attributes=['sAMAccountName'])


class ADWSClient:
    """Directory collection backend speaking ADWS (net.tcp/9389) via SOAPy, exposing the
    same surface as ADClient."""

    def __init__(self, domain, url):
        self.domain = domain
        self.base_dn = ",".join([f"DC={part}" for part in domain.split('.')])
        parts = urlsplit(url)
        self.host = parts.hostname
        self.username = (parts.username or '').rsplit('\\', 1)[-1]
        self._secret = parts.password
        self._auth_method = parts.scheme.split('+', 1)[-1]
        self._pull_client = None
        self._server_info = {}
        self.msldap_client = _MsldapClient(self)

    def _build_auth(self):
        method = self._auth_method
        if method == 'kerberos-aes':
            raise NotImplementedError("ADWS doesn't support AES-key Kerberos (SOAPy: ccache only). Use --protocol ldap.")
        if method.startswith('kerberos'):
            if method == 'kerberos-rc4':
                raise NotImplementedError("ADWS doesn't support Kerberos with an NT hash (SOAPy: ccache only). Use --protocol ldap.")
            if not os.environ.get('KRB5CCNAME'):
                raise RuntimeError("ADWS Kerberos auth requires KRB5CCNAME to point to a valid credential cache.")
            return KerberosAuth(kdc_host=self.host)
        if method == 'ntlm-nt':
            return NTLMAuth(hashes=self._secret)
        return NTLMAuth(password=self._secret)

    async def connect(self):
        if not _ADWS_AVAILABLE:
            raise ImportError(f"ADWS support requires the SOAPy package: {_ADWS_IMPORT_ERROR}")

        auth = self._build_auth()
        self._pull_client = await asyncio.to_thread(ADWSConnect.pull_client, self.host, self.domain, self.username, auth)
        resource_client = await asyncio.to_thread(ADWSConnect, self.host, self.domain, self.username, auth, "Resource")
        try:
            self._server_info = await asyncio.to_thread(get_rootdse_contexts, resource_client)
        except Exception:
            self._server_info = {}
        finally:
            await asyncio.to_thread(resource_client._nmf._sock.close)

    async def disconnect(self):
        if self._pull_client:
            await asyncio.to_thread(self._pull_client._nmf._sock.close)

    async def get_ADobjects(self, custom_base_dn=None, custom_filter=None, custom_attributes=None):
        attributes = None
        if custom_attributes:
            names = [a.decode() if isinstance(a, bytes) else a for a in custom_attributes if a not in ('*', b'*')]
            attributes = names or None
        et = await asyncio.to_thread(self._pull_client.pull, query=custom_filter or '(objectClass=*)',
                                      basedn=custom_base_dn or self.base_dn, attributes=attributes)
        return _adws_parse_items(et, self._pull_client)

    async def add_DNSentry(self, domain, hostname, ip):
        auth = self._build_auth()
        try:
            ok = await asyncio.to_thread(add_dns_record_adws, f'{hostname}.{domain}', ip, self.username, self.host, domain, auth)
            return ok, None
        except Exception as e:
            return False, e

    async def del_DNSentry(self, domain, hostname):
        auth = self._build_auth()
        try:
            ok = await asyncio.to_thread(remove_dns_record_adws, f'{hostname}.{domain}', None,
                                          self.username, self.host, domain, auth, ldapdelete=True)
            return ok, None
        except Exception as e:
            return False, e


def build_ad_client(protocol, domain, url):
    """Pick the directory-collection backend: LDAP (msldap, default) or ADWS (SOAPy)."""
    return ADWSClient(domain=domain, url=url) if protocol == 'adws' else ADClient(domain=domain, url=url)


from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.commons.interfaces.file import SMBFile
from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.protocol.smb2.commands.create import CreateDisposition, CreateOptions, ShareAccess, FileAccessMask, FileAttributes
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

    async def list_named_pipes(self):
        host = self.smbconn.target.get_hostname_or_ip()
        tree, err = await self.smbconn.tree_connect(f"\\\\{host}\\IPC$")
        if err:
            raise err
        fid, err = await self.smbconn.create(
            tree.tree_id, "",
            FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_READ_DATA,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT,
            CreateDisposition.FILE_OPEN,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
        )
        if err:
            raise err
        pipes = []
        while True:
            entries, err = await self.smbconn.query_directory(tree.tree_id, fid)
            if err or not entries:
                break
            pipes += [e.FileName for e in entries if e.FileName not in ('.', '..')]
        await self.smbconn.close(tree.tree_id, fid)
        return sorted(pipes)

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
        except Exception as e:
            logging.warning(f"RemoteRegistry connection failed: {e}")

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
