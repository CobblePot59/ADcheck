from adcheck.libs.impacket.structure import Structure
from msldap.commons.factory import LDAPConnectionFactory
from msldap.connection import MSLDAPClientConnection
import socket
import dns.resolver


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)

def new_record(dc_ip, domain):
    nr = DNS_RECORD()
    nr['Type'] = 1 # Type 1 = A record
    nr['Serial'] = get_next_serial(dc_ip=dc_ip, domain=domain)
    nr['TtlSeconds'] = 180
    nr['Rank'] = 240 # From authoritive zone
    return nr

def get_next_serial(dc_ip, domain):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    dnsresolver.nameservers = [dc_ip]

    res = dnsresolver.resolve(domain, 'SOA',tcp=False)
    for answer in res:
        return answer.serial + 1


class ADClient:
    def __init__(self, domain, url):
        self.domain = domain
        self.base_dn = f"DC={domain.split('.')[0]},DC={domain.split('.')[1]}"
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
            _ , self.msldap_client_conn_err = await msldap_client_conn.bind()

        await self.msldap_client.connect()
        return self.msldap_client

    async def disconnect(self):
        await self.msldap_conn.disconnect()
        await self.msldap_client.disconnect()

    async def get_ADobjects(self, custom_base_dn=None, custom_filter=None, custom_attributes=None):
        ad_objects = self.msldap_conn.pagedsearch(
            base=custom_base_dn or self.base_dn,
            query=custom_filter or '(objectClass=*)',
            attributes=custom_attributes or [b'*']
        )

        ad_object = [ad_object.get('attributes') async for ad_object, e in ad_objects]
        return ad_object

    async def add_DNSentry(self, domain, dc_ip, target, data):
        dns_root = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{self.base_dn}"

        record_dn = f'DC={target},{dns_root}'
        node_data = {
            'objectClass': ['top', 'dnsNode'],
            'objectCategory': f'CN=Dns-Node,CN=Schema,CN=Configuration,{self.base_dn}', # Schema is in the root domain (take if from schemaNamingContext to be sure)
            'dNSTombstoned': False,
            'name': target
        }

        record = new_record(dc_ip=dc_ip, domain=domain)
        record['Data'] = DNS_RPC_RECORD_A()
        record['Data'].fromCanonical(data)
        node_data['dnsRecord'] = record.getData()
        return await self.msldap_conn.add(record_dn, node_data)

    async def del_DNSentry(self, domain, target):
        dns_root = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{self.base_dn}"

        record_dn = f'DC={target},{dns_root}'
        return await self.msldap_conn.delete(record_dn)