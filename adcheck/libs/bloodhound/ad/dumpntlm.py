#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Dump remote host information in ntlm authentication model, without credentials.
#   For SMB protocols (1 and 2/3), it's easy to use SMBConnection class (thanks to @agsolino), 
#   but since negotiate response is not available in original classes, 
#   we made out custom classes based on them.
#   The usefull information in negotiate response are "Dialect Version", "Signing Options",
#   "Maximum bytes allowed per smb request" and "Servers time information".
#   The point is sometimes server dosn't include "boot time" in response. But we show it,
#   when available, in this script.
# 
#   It's very easy to use:
#       python dumpntlm.py 192.168.1.63
#
# Author:
#   Alex Romero (@NtAlexio2)
#
# Reference for:
#   [MS-SMB2]
#   [MS-RPCE]
#
# NOTE:
#   This is modified version of original dumpntlm.py here:
#   https://github.com/NtAlexio2/impacket/blob/master/examples/dumpntlm.py
#   The relevant pull request (https://github.com/SecureAuthCorp/impacket/pull/1404)
#   to Impacket is not accepted at the time of adding this file to BloodHound.py repo.
#

import os
import socket
import string, random

from impacket import nmb, ntlm
from impacket.smb import SMB, NewSMBPacket, SMBCommand, SMBNTLMDialect_Parameters,\
    SMBNTLMDialect_Data, SMBExtended_Security_Parameters, SMBExtended_Security_Data, UnsupportedFeature,\
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Parameters, SMBSessionSetupAndX_Extended_Response_Parameters,\
    SMBSessionSetupAndX_Extended_Response_Data, SMB_DIALECT
from impacket.smb3structs import *
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.nt_errors import STATUS_SUCCESS
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import *



class RPC:
    def __init__(self, target) -> None:
        self.MaxTrasmitionSize = 0
        self._initializeTransport(target)
    
    def GetChallange(self):
        ntlmChallenge = None
        packet = self._create_bind_request()
        self._rpctransport.send(packet.get_packet())
        buffer = self._rpctransport.recv()
        if buffer != 0:
            response = MSRPCHeader(buffer)
            bindResp = MSRPCBindAck(response.getData())
            
            self.MaxTrasmitionSize = bindResp['max_rfrag']
            
            ntlmChallenge = ntlm.NTLMAuthChallenge(bindResp['auth_data'])
        return ntlmChallenge

    def _initializeTransport(self, target):
        self._rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s[135]' % target)
        self._rpctransport.set_credentials('', '', '', '', '')
        self._rpctransport.set_dport(135)
        self._rpctransport.connect()
    
    def _create_bind_request(self):
        bind = MSRPCBind()
        item = CtxItem()
        item['AbstractSyntax'] = epm.MSRPC_UUID_PORTMAP
        item['TransferSyntax'] = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
        item['ContextID'] = 0
        item['TransItems'] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet['type'] = MSRPC_BIND
        packet['pduData'] = bind.getData()
        packet['call_id'] = 1

        auth = ntlm.getNTLMSSPType1('', '', signingRequired=True, use_ntlmv2=True)
        sec_trailer = SEC_TRAILER()
        sec_trailer['auth_type']   = RPC_C_AUTHN_WINNT
        sec_trailer['auth_level']  = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
        sec_trailer['auth_ctx_id'] = 0 + 79231 
        pad = (4 - (len(packet.get_packet()) % 4)) % 4
        if pad != 0:
           packet['pduData'] += b'\xFF'*pad
           sec_trailer['auth_pad_len']=pad
        packet['sec_trailer'] = sec_trailer
        packet['auth_data'] = auth

        return packet


class SMB1:
    def __init__(self, remote_name, remote_host, my_name=None, 
                    sess_port=445, timeout=60, session=None, negSessionResponse=None):
        self._uid = 0
        self._dialects_data = None
        self._SignatureRequired = False
        self._dialects_parameters = None
        self.__flags1 = SMB.FLAGS1_PATHCASELESS | SMB.FLAGS1_CANONICALIZED_PATHS
        self.__flags2 = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES
        self.__timeout = timeout
        self._session = session
        self._my_name = my_name
        self._auth = None

        if session is None:
            self._session = nmb.NetBIOSTCPSession(my_name, remote_name, remote_host, nmb.TYPE_SERVER, sess_port, self.__timeout)

        self._negotiateResponse = self._negotiateSession(negSessionResponse)

    def GetNegotiateResponse(self):
        return self._negotiateResponse

    def GetChallange(self):
        packet = NewSMBPacket()
        if self._SignatureRequired:
           packet['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
        sessionSetup = self._createSessionSetupRequest()
        packet.addCommand(sessionSetup)
        self.send(packet)
        packet = self.receive()
        if packet.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
            self._uid = packet['Uid']
            sessionResponse   = SMBCommand(packet['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = packet['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            self._respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])
            ntlmChallenge = ntlm.NTLMAuthChallenge(self._respToken['ResponseToken'])
            self._session.close()
            return ntlmChallenge

    def send(self, negoPacket):
        negoPacket['Uid'] = self._uid
        negoPacket['Pid'] = (os.getpid() & 0xFFFF)
        negoPacket['Flags1'] |= self.__flags1
        negoPacket['Flags2'] |= self.__flags2
        self._session.send_packet(negoPacket.getData())

    def receive(self):
        r = self._session.recv_packet(self.__timeout)
        return NewSMBPacket(data = r.get_trailer())

    def _negotiateSession(self, negPacket = None):
        def parsePacket(negoPacket):
            if negoPacket['Flags2'] & SMB.FLAGS2_UNICODE:
                self.__flags2 |= SMB.FLAGS2_UNICODE

            if negoPacket.isValidAnswer(SMB.SMB_COM_NEGOTIATE):
                sessionResponse = SMBCommand(negoPacket['Data'][0])
                self._dialects_parameters = SMBNTLMDialect_Parameters(sessionResponse['Parameters'])
                self._dialects_data = SMBNTLMDialect_Data()
                self._dialects_data['ChallengeLength'] = self._dialects_parameters['ChallengeLength']
                self._dialects_data.fromString(sessionResponse['Data'])
                if self._dialects_parameters['Capabilities'] & SMB.CAP_EXTENDED_SECURITY:
                    self._dialects_parameters = SMBExtended_Security_Parameters(sessionResponse['Parameters'])
                    self._dialects_data = SMBExtended_Security_Data(sessionResponse['Data'])
                    if self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SIGNATURES_REQUIRED:
                        self._SignatureRequired = True
                else:
                    if self._dialects_parameters['DialectIndex'] == 0xffff:
                        raise UnsupportedFeature("Remote server does not know NT LM 0.12")

                return self._wrapper(sessionResponse)

        if negPacket is None:
            negoPacket = NewSMBPacket()
            negSession = SMBCommand(SMB.SMB_COM_NEGOTIATE)
            self.__flags2 = self.__flags2 | SMB.FLAGS2_EXTENDED_SECURITY

            negSession['Data'] = b'\x02NT LM 0.12\x00'
            negoPacket.addCommand(negSession)
            self.send(negoPacket)

            negoPacket = self.receive()
            return parsePacket(negoPacket)

        return parsePacket(NewSMBPacket(data = negPacket))

    def _createSessionSetupRequest(self):
        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Data'] = SMBSessionSetupAndX_Extended_Data()
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Parameters']['MaxBufferSize'] = 61440
        sessionSetup['Parameters']['MaxMpxCount'] = 2
        sessionSetup['Parameters']['VcNumber'] = 1
        sessionSetup['Parameters']['SessionKey'] = 0
        sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY | SMB.CAP_USE_NT_ERRORS | SMB.CAP_UNICODE | SMB.CAP_LARGE_READX | SMB.CAP_LARGE_WRITEX

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        self._auth = ntlm.getNTLMSSPType1(self._my_name, '', self._SignatureRequired, use_ntlmv2=True)
        blob['MechToken'] = self._auth.getData()

        sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob'] = blob.getData()
        sessionSetup['Data']['NativeOS']      = 'U\x00n\x00i\x00x\x00\x00\x00'
        sessionSetup['Data']['NativeLanMan']  = 'S\x00a\x00m\x00b\x00a\x00\x00'

        return sessionSetup

    def _wrapper(self, sessionResponse):
        sessionResponse['DialectRevision'] = SMB_DIALECT
        if self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SIGNATURES_ENABLED:
            sessionResponse['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED
            if self._SignatureRequired:
                sessionResponse['SecurityMode'] |= SMB2_NEGOTIATE_SIGNING_REQUIRED
        sessionResponse['MaxReadSize'] = self._dialects_parameters['MaxBufferSize']
        sessionResponse['MaxWriteSize'] = self._dialects_parameters['MaxBufferSize']
        sessionResponse['SystemTime'] = self._to_long_filetime(self._dialects_parameters['LowDateTime'], self._dialects_parameters['HighDateTime'])
        sessionResponse['ServerStartTime'] = 0 # SMB1 has not boot time totally
        return sessionResponse

    def _to_long_filetime(self, dwLowDateTime, dwHighDateTime):
        temp_time = dwHighDateTime
        temp_time <<= 32
        temp_time |= dwLowDateTime
        return temp_time


class SMB3:
    def __init__(self, remote_name, remote_host, my_name=None, 
                    sess_port=445, timeout=60, session=None, negSessionResponse=None):
        self._NetBIOSSession = session
        self._sequenceWindow = 0
        self._sessionId = 0
        self._timeout = timeout
        self._auth = None

        if session is None:
            self._NetBIOSSession = nmb.NetBIOSTCPSession(my_name, remote_name, remote_host, nmb.TYPE_SERVER, sess_port, timeout)
        else:
            self._sequenceWindow += 1
        
        self._negotiateResponse = self._negotiateSession(negSessionResponse)

    def GetNegotiateResponse(self):
        return self._negotiateResponse

    def GetChallange(self):
        packet = self._createSessionSetupRequest(self._negotiateResponse['DialectRevision'])

        self.send(packet)
        self._answer = self.receive()

        sessionSetupResponse = SMB2SessionSetup_Response(self._answer['Data'])
        self._respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])
        ntlmChallenge = ntlm.NTLMAuthChallenge(self._respToken['ResponseToken'])
        self._NetBIOSSession.close()
        return ntlmChallenge

    def send(self, packet):
        packet['MessageID'] = self._sequenceWindow
        self._sequenceWindow += 1

        packet['SessionID'] = self._sessionId
        packet['CreditCharge'] = 1
        messageId = packet['MessageID']
        data = packet.getData()
        self._NetBIOSSession.send_packet(data)

        return messageId

    def receive(self):
        data = self._NetBIOSSession.recv_packet(self._timeout)
        packet = SMB2Packet(data.get_trailer())
        return packet

    def _negotiateSession(self, negSessionResponse = None):
        currentDialect = SMB2_DIALECT_WILDCARD
        if negSessionResponse is not None:
            negotiateResponse = SMB2Negotiate_Response(negSessionResponse['Data'])
            currentDialect = negotiateResponse['DialectRevision']

        if currentDialect == SMB2_DIALECT_WILDCARD:
            packet = SMB2Packet()
            packet['Command'] = SMB2_NEGOTIATE
            negSession = SMB2Negotiate()
            negSession['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED
            negSession['Capabilities'] = SMB2_GLOBAL_CAP_ENCRYPTION
            negSession['ClientGuid'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])
            negSession['Dialects'] = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]
            negSession['DialectCount'] = len(negSession['Dialects'])
            packet['Data'] = negSession

            self.send(packet)
            answer = self.receive()
            if answer.isValidAnswer(STATUS_SUCCESS):
                negotiateResponse = SMB2Negotiate_Response(answer['Data'])

        return negotiateResponse

    def _createSessionSetupRequest(self, dialect):
        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        
        self._auth = ntlm.getNTLMSSPType1('', '', False)
        blob['MechToken'] = self._auth.getData()

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer']               = blob.getData()

        packet = SMB2Packet()
        if dialect >= SMB2_DIALECT_30:
            packet = SMB3Packet()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        return packet


class SmbConnection:
    def __init__(self, ip, hostname, port) -> None:
        self.target      = ip
        self.hostname    = hostname
        self._sess_port  = int(port)
        self._timeout    = 60
        self._myName     = self._get_my_name()
        self._nmbSession = None
        self._SMBConnection = None

    def NegotiateSession(self):
        flags1 = SMB.FLAGS1_PATHCASELESS | SMB.FLAGS1_CANONICALIZED_PATHS
        flags2 = SMB.FLAGS2_EXTENDED_SECURITY | SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES

        negoData = '\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'
        if self._sess_port == nmb.NETBIOS_SESSION_PORT:
            negoData = '\x02NT LM 0.12\x00\x02SMB 2.002\x00'

        packet = self._negotiateSessionWildcard(True, flags1=flags1, flags2=flags2, data=negoData)

        if packet[0:1] == b'\xfe':
            self._SMBConnection = SMB3(self.hostname, self.target, self._myName, self._sess_port, 
                                        self._timeout, session=self._nmbSession, negSessionResponse=SMB2Packet(packet))
        else:
            self._SMBConnection = SMB1(self.hostname, self.target, self._myName, self._sess_port, 
                                        self._timeout, session=self._nmbSession, negSessionResponse=packet)
        return self._SMBConnection.GetNegotiateResponse()

    def GetChallange(self):
        return self._SMBConnection.GetChallange()

    def _negotiateSessionWildcard(self, extended_security=True, flags1=0, flags2=0, data=None):
        tries = 0
        smbp = NewSMBPacket()
        smbp['Flags1'] = flags1
        smbp['Flags2'] = flags2 | SMB.FLAGS2_UNICODE
        response = None
        while tries < 2:
            self._nmbSession = nmb.NetBIOSTCPSession(self._myName, self.hostname, self.target, nmb.TYPE_SERVER, self._sess_port, self._timeout)
            negSession = SMBCommand(SMB.SMB_COM_NEGOTIATE)
            if extended_security is True:
                smbp['Flags2'] |= SMB.FLAGS2_EXTENDED_SECURITY
            negSession['Data'] = data
            smbp.addCommand(negSession)
            self._nmbSession.send_packet(smbp.getData())

            try:
                response = self._nmbSession.recv_packet(self._timeout)
                break
            except nmb.NetBIOSError:
                smbp['Flags2'] |= SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_LONG_NAMES | SMB.FLAGS2_UNICODE
                smbp['Data'] = []

            tries += 1

        if response is None:
            raise Exception('No answer!')

        return response.get_trailer()

    def _get_my_name(self):
        myName = socket.gethostname()
        i = myName.find('.')
        if i > -1:
            myName = myName[:i]
        return myName


class DumpNtlm:
    def __init__(self, ip, hostname, port) -> None:
        self.target = ip
        self.hostname = hostname
        self._sess_port = int(port)
        self._timeout = 60

    def GetInfo(self) -> dict:
        if self._sess_port in [139, 445]:
            return self.GetSmbInfo()
        elif  self._sess_port in [135]:
            return self.GetRpcInfo()

    def GetRpcInfo(self) -> dict:
        rpc = RPC(self.target)
        ntlmChallenge = rpc.GetChallange()
        return self.GetChallangeInfo(ntlmChallenge)

    def GetSmbInfo(self) -> dict:
        connection = SmbConnection(self.target, self.hostname, self._sess_port)
        negotiation = connection.NegotiateSession()
        ntlmChallenge = connection.GetChallange()
        return self.GetChallangeInfo(ntlmChallenge)

    def GetChallangeInfo(self, challange) -> dict:
        info = {}
        if challange['TargetInfoFields_len'] > 0:
            av_pairs = ntlm.AV_PAIRS(challange['TargetInfoFields'][:challange['TargetInfoFields_len']])
            if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                try:
                    info['name'] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                except:
                    pass
            if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                try:
                    info['domain'] = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                except:
                    pass
            if av_pairs[ntlm.NTLMSSP_AV_DNS_TREENAME] is not None:
                try:
                    info['dns_tree'] = av_pairs[ntlm.NTLMSSP_AV_DNS_TREENAME][1].decode('utf-16le')
                except:
                    pass
            if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                try:
                    info['dns_domain'] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode('utf-16le')
                except:
                    pass
            if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                try:
                    info['dns_host'] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode('utf-16le')
                except:
                    pass
        return info
