# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
# SPDX-FileCopyrightText: 2010 Markus Koetter & Tan Kean Siong
# SPDX-FileCopyrightText: 2011 Markus Koetter
# SPDX-FileCopyrightText: 2015 Katarina Durechova
# SPDX-FileCopyrightText: 2017 Tan Kean Siong
# SPDX-FileCopyrightText: 2016-2017 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import inspect
import socket
import struct
import hashlib
import logging
import os
import secrets
import tempfile
from uuid import UUID

from . import rpcservices

from .include.smbfields import (
    CAP_EXTENDED_SECURITY,
    DCERPC_Ack_CtxItem,
    DCERPC_Bind_Ack,
    DCERPC_Header,
    NBTSession,
    RAP_OP_NETSHAREENUM,
    RAP_Request,
    RAP_Response,
    SMB_COM_CLOSE,
    SMB_COM_DELETE,
    SMB_COM_ECHO,
    SMB_COM_LOGOFF_ANDX,
    SMB_COM_NEGOTIATE,
    SMB_COM_NT_CREATE_ANDX,
    SMB_COM_NT_TRANSACT,
    SMB_COM_OPEN_ANDX,
    SMB_COM_QUERY_INFORMATION_DISK,
    SMB_COM_READ_ANDX,
    SMB_COM_SESSION_SETUP_ANDX,
    SMB_COM_TRANSACTION,
    SMB_COM_TRANSACTION2,
    SMB_COM_TRANSACTION2_SECONDARY,
    SMB_COM_TRANSACTION_SECONDARY,
    SMB_COM_TREE_CONNECT_ANDX,
    SMB_COM_TREE_DISCONNECT,
    SMB_COM_WRITE,
    SMB_COM_WRITE_ANDX,
    SMB_Close,
    SMB_Close_Response,
    SMB_Commands,
    SMB_Data,
    SMB_Delete_Request,
    SMB_Delete_Response,
    SMB_FA_ARCHIVE,
    SMB_FA_DIRECTORY,
    SMB_FA_HIDDEN,
    SMB_FA_NORMAL,
    SMB_FA_SYSTEM,
    SMB_FLAGS2_EXT_SEC,
    SMB_FLAGS2_UNICODE,
    SMB_Header,
    SMB_Logoff_AndX,
    SMB_NT_Trans_Request,
    SMB_NT_Trans_Response,
    SMB_NTcreate_AndX_Request,
    SMB_NTcreate_AndX_Response,
    SMB_Negociate_Protocol_Request_Counts,
    SMB_Negociate_Protocol_Response,
    SMB_Open_AndX_Request,
    SMB_Open_AndX_Response,
    SMB_Query_Information_Disk_Response,
    SMB_Read_AndX_Request,
    SMB_Read_AndX_Response,
    SMB_Sessionsetup_AndX_Request2,
    SMB_Sessionsetup_AndX_Response2,
    SMB_Sessionsetup_ESEC_AndX_Request,
    SMB_Sessionsetup_ESEC_AndX_Response,
    SMB_Trans2_Commands,
    SMB_TRANS2_FIND_FIRST2,
    SMB_TRANS2_QUERY_FS_INFORMATION,
    SMB_TRANS2_SESSION_SETUP,
    SMB_Trans2_FIND_FIRST2_Response,
    SMB_Trans2_QUERY_FS_INFO_Response,
    SMB_Trans2_Request,
    SMB_Trans2_Response,
    SMB_Trans2_Secondary_Request,
    SMB_Trans_Request,
    SMB_Trans_Response,
    SMB_Trans_Response_Simple,
    SMB_Trans_Secondary_Request,
    SMB_Treeconnect_AndX_Request,
    SMB_Treeconnect_AndX_Response,
    SMB_Treeconnect_AndX_Response2,
    SMB_Treeconnect_AndX_Response_Extended,
    SMB_Treedisconnect,
    SMB_Write_AndX_Request,
    SMB_Write_AndX_Response,
    SMB_Write_Request,
    SMB_Write_Response,
    TRANS_NMPIPE_PEEK,
    TRANS_NMPIPE_TRANSACT,
)
from .rpcservices import __shares__
from .include.gssapifields import GSSAPI, SPNEGO, NegTokenTarg
from .include.ntlmfields import (
    AV_PAIR,
    NTLM_Challenge,
    NTLM_Negotiate,
    NTLMSSP_Header,
    NTLMSSP_NEGOTIATE_TARGET_INFO,
    NTLMSSP_NEGOTIATE_VERSION,
)
from .include.packet import Raw
from .include.asn1.ber import BER_len_dec, BER_len_enc, BER_identifier_dec
from .include.asn1.ber import BER_CLASS_APP, BER_CLASS_CON, BER_identifier_enc
from .include.asn1.ber import BER_Exception
from dionaea.util import calculate_doublepulsar_opcode, xor
from dionaea.core import incident, connection, g_dionaea
from dionaea.ndrlib import NDR32_UUID, NDR64_UUID

TRANSFER_SYNTAX_NAMES = {
    NDR32_UUID: "NDR32",
    NDR64_UUID: "NDR64",
}

smblog = logging.getLogger("SMB")

STATE_START = 0
STATE_SESSIONSETUP = 1
STATE_TREECONNECT = 2
STATE_NTCREATE = 3
STATE_NTWRITE = 4
STATE_NTREAD = 5

registered_services = {}


def register_rpc_service(service):
    uuid = service.uuid
    registered_services[uuid] = service


def build_ntlm_target_info(domain_name, computer_name):
    """Build NTLM TargetInfo (AV_PAIRs) for NTLMv2 authentication.

    Returns tuple of (target_name_bytes, target_info_bytes) where:
    - target_name_bytes: UTF-16LE encoded domain name for TargetName field
    - target_info_bytes: Concatenated AV_PAIRs for TargetInfo field
    """
    # Encode names as UTF-16LE (without BOM)
    domain_utf16 = domain_name.encode("utf-16-le")
    computer_utf16 = computer_name.encode("utf-16-le")

    # Build AV_PAIRs
    # MsvAvNbDomainName (Id=2)
    av_domain = AV_PAIR(Id=2, Value=domain_utf16)
    # MsvAvNbComputerName (Id=1)
    av_computer = AV_PAIR(Id=1, Value=computer_utf16)
    # MsvAvEOL (Id=0) - end of list
    av_eol = AV_PAIR(Id=0, Value=b"")

    target_info = av_domain.build() + av_computer.build() + av_eol.build()

    return domain_utf16, target_info


class smbd(connection):
    shared_config_values = ["config"]

    # DoublePulsar signature and XOR key for payload encryption/decryption
    # Generated randomly at startup to avoid fingerprinting
    # Signature is sent in PING response, attackers calculate XOR key from it
    doublepulsar_signature = secrets.randbits(32)

    @staticmethod
    def _calculate_xor_key_from_signature(sig):
        """Calculate XOR key from signature per DoublePulsar protocol."""
        x = (2 * sig) ^ (
            (((sig & 0xFF00) | (sig << 16)) << 8)
            | (((sig >> 16) | (sig & 0xFF0000)) >> 8)
        )
        return x & 0xFFFFFFFF

    # XOR key derived from signature (little-endian result)
    doublepulsar_xor_key = _calculate_xor_key_from_signature(doublepulsar_signature)

    @classmethod
    def get_doublepulsar_xor_key_bytes(cls):
        """Convert the XOR key to a bytearray for XOR operations (little-endian)."""
        key = cls.doublepulsar_xor_key
        return bytearray(
            [key & 0xFF, (key >> 8) & 0xFF, (key >> 16) & 0xFF, (key >> 24) & 0xFF]
        )

    def __init__(self, proto="tcp", config=None):
        connection.__init__(self, "tcp")
        self.state = {
            "lastcmd": None,
            "readcount": 0,
            "stop": False,
        }
        self.buf = b""
        self.buf2 = b""  # ms17-010 SMB_COM_TRANSACTION2
        self.trans_params = b""  # SMB_COM_TRANSACTION_SECONDARY accumulated params
        self.trans_data = b""  # SMB_COM_TRANSACTION_SECONDARY accumulated data
        self.trans_total_params = 0  # expected total param count
        self.trans_total_data = 0  # expected total data count
        self.trans_name = ""  # transaction name from primary TRANSACTION
        self.outbuf = None
        self.fids = {}
        self.printer = b""  # spoolss file "queue"

        self.config = None

    def apply_config(self, config=None):
        # Avoid import loops
        from .extras import SmbConfig

        self.config = SmbConfig(config=config)
        # Set the global OS_TYPE value
        # ToDo: This is a quick and dirty hack
        from . import rpcservices

        rpcservices.__shares__ = self.config.shares
        rpcservices.OS_TYPE = self.config.os_type
        rpcservices.__server_name__ = self.config.server_name

    def handle_established(self):
        # self.timeouts.sustain = 120
        self.timeouts.idle = 120
        # self._in.accounting.limit  = 2000*1024
        # self._out.accounting.limit = 2000*1024
        # Skip self.processors() - SMB handles shellcode detection via DoublePulsar
        # XOR decode path. Running the stream processor on encrypted data produces
        # false positives.

    def _process_doublepulsar_payload(self):
        """Process accumulated DoublePulsar payload data."""
        if len(self.buf2) == 0:
            return

        smblog.info(
            "Processing DoublePulsar payload: %d bytes",
            len(self.buf2),
        )

        key = smbd.get_doublepulsar_xor_key_bytes()
        xor_output = xor(self.buf2, key)
        hash_raw = hashlib.sha256(self.buf2).hexdigest()
        hash_decoded = hashlib.sha256(xor_output).hexdigest()

        # Look for MZ header to find embedded PE
        offset = 0
        for i, c in enumerate(xor_output):
            if (xor_output[i] == 0x4D and xor_output[i + 1] == 0x5A) and xor_output[
                i + 2
            ] == 0x90:
                offset = i
                break

        if offset > 0:
            smblog.info(
                "DoublePulsar payload: MZ found at offset %d, SHA256 raw=%s decoded=%s",
                offset,
                hash_raw,
                hash_decoded,
            )
            # Emit decoded shellcode (loader stub before PE) for speakeasy analysis
            shellcode_data = bytes(xor_output[:offset])
            if len(shellcode_data) > 0:
                smblog.info(
                    "DoublePulsar shellcode: %d bytes (PE loader stub)",
                    len(shellcode_data),
                )
                icd_sc = incident("dionaea.shellcode.detected")
                icd_sc.set("data", shellcode_data)
                # TODO: detect arch from shellcode instead of assuming x86
                icd_sc.set("arch", "x86")
                icd_sc.set("offset", 0)
                icd_sc.set("con", self)
                icd_sc.report()
        else:
            smblog.info(
                "DoublePulsar payload: no MZ header, SHA256 raw=%s decoded=%s",
                hash_raw,
                hash_decoded,
            )
            # Entire decoded payload is shellcode (no embedded PE)
            shellcode_data = bytes(xor_output)
            if len(shellcode_data) > 0:
                smblog.info(
                    "DoublePulsar shellcode: %d bytes",
                    len(shellcode_data),
                )
                icd_sc = incident("dionaea.shellcode.detected")
                icd_sc.set("data", shellcode_data)
                # TODO: detect arch from shellcode instead of assuming x86
                icd_sc.set("arch", "x86")
                icd_sc.set("offset", 0)
                icd_sc.set("con", self)
                icd_sc.report()

        dionaea_config = g_dionaea.config().get("dionaea", {})
        download_dir = dionaea_config.get("download.dir")
        download_suffix = dionaea_config.get("download.suffix", ".tmp")

        fp = tempfile.NamedTemporaryFile(
            delete=False,
            prefix="smb-",
            suffix=download_suffix,
            dir=download_dir,
        )
        fp.write(xor_output[offset:])
        fp.close()
        self.buf2 = b""

        icd = incident("dionaea.download.complete")
        icd.path = fp.name
        icd.url = ""
        icd.con = self
        icd.report()
        os.unlink(fp.name)

    def handle_io_in(self, data: bytes) -> int:
        try:
            p = NBTSession(data, _ctx=self)
        except Exception as e:
            smblog.warning(
                "NBTSession packet parsing failed: %s (len=%d, data=%s)",
                str(e),
                len(data),
                data[:16].hex() if data else "empty",
            )
            return len(data)

        if len(data) < (p.LENGTH + 4):
            # we probably do not have the whole packet yet -> return 0
            return 0

        if p.TYPE == 0x81:
            self.send(NBTSession(TYPE=0x82).build())
            return len(data)
        elif p.TYPE != 0:
            # we currently do not handle anything else
            return len(data)

        if p.haslayer(SMB_Header) and p[SMB_Header].Start != b"\xffSMB":
            start = p[SMB_Header].Start
            if start == b"\xfeSMB":
                smblog.info(
                    "SMB2/SMB3 from %s:%d - not supported, closing",
                    self.remote.host,
                    self.remote.port,
                )
            else:
                smblog.warning(
                    "Unknown SMB header from %s:%d: %r",
                    self.remote.host,
                    self.remote.port,
                    start,
                )
            self.close()
            return len(data)

        p.show()
        r = None

        # this is one of the things you have to love, it violates the spec, but
        # has to work ...
        if (
            p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request)
            and p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).WordCount == 13
        ):
            smblog.debug("recoding session setup request!")
            p.getlayer(SMB_Header).decode_payload_as(SMB_Sessionsetup_AndX_Request2)
            x = p.getlayer(SMB_Sessionsetup_AndX_Request2)
            x.show()

        r = self.process(p)
        smblog.debug("packet: %s" % p.summary())

        if p.haslayer(Raw):
            smblog.debug("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

        # i = incident("dionaea.module.python.smb.info")
        # i.con = self
        # i.direction = 'in'
        # i.data = p.summary()
        # i.report()

        if self.state["stop"]:
            smblog.info("faint death.")
            return len(data)

        if r:
            smblog.debug("response: %s" % r.summary())
            r.show()

            # i = incident("dionaea.module.python.smb.info")
            # i.con = self
            # i.direction = 'out'
            # i.data = r.summary()
            # i.report()

            # r.build()
            # r.show2()
            self.send(r.build())
        else:
            smblog.error("process() returned None.")

        if p.haslayer(Raw):
            smblog.debug("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()
            # some rest seems to be not parsed correctly
            # could be start of some other packet, junk, or failed packet dissection
            # TODO: recover from this...
            return len(data) - len(p.getlayer(Raw).load)

        return len(data)

    def process(self, p):
        r = ""
        rp = None
        # self.state['readcount'] = 0
        # if self.state == STATE_START and p.getlayer(SMB_Header).Command ==
        # 0x72:
        rstatus = 0
        smbh = p.getlayer(SMB_Header)
        Command = smbh.Command
        if Command == SMB_COM_NEGOTIATE:
            # Negociate Protocol -> Send response that supports minimal features in NT LM 0.12 dialect
            # (could be randomized later to avoid detection - but we need more dialects/options support)
            r = SMB_Negociate_Protocol_Response(
                OemDomainName=self.config.oem_domain_name + "\0",
                ServerName=self.config.server_name + "\0",
            )
            # we have to select dialect
            c = 0
            tmp = p.getlayer(SMB_Negociate_Protocol_Request_Counts)
            dialects = []
            while c < len(tmp.Requests):
                request = tmp.Requests[c]
                dialect = request.BufferData.decode("ascii", errors="replace").rstrip(
                    "\x00"
                )
                dialects.append(dialect)
                if dialect.find("NT LM 0.12") != -1:
                    break
                c += 1

            r.DialectIndex = c
            smblog.info(
                "SMB Negotiate from %s:%d - dialects: %s",
                self.remote.host,
                self.remote.port,
                ", ".join(dialects) if dialects else "none",
            )

            # r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY
            if not p.Flags2 & SMB_FLAGS2_EXT_SEC:
                r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY

        # elif self.state == STATE_SESSIONSETUP and
        # p.getlayer(SMB_Header).Command == 0x73:
        elif Command == SMB_COM_SESSION_SETUP_ANDX:
            smblog.info(
                "SMB Session Setup from %s:%d",
                self.remote.host,
                self.remote.port,
            )
            if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request):
                r = SMB_Sessionsetup_ESEC_AndX_Response(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain,
                )
                ntlmssp = None
                sb = p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).SecurityBlob

                if sb.startswith(b"NTLMSSP"):
                    # GSS-SPNEGO without OID
                    ntlmssp = NTLMSSP_Header(sb)
                    ntlmssp.show()
                    # FIXME what is a proper reply?
                    # currently there windows calls Sessionsetup_AndX2_request
                    # after this one with bad reply
                    if ntlmssp.MessageType == 1:
                        r.Action = 0
                        ntlmnegotiate = ntlmssp.getlayer(NTLM_Negotiate)

                        # Build TargetInfo for NTLMv2 authentication
                        target_name, target_info = build_ntlm_target_info(
                            self.config.primary_domain,
                            self.config.server_name,
                        )

                        neg_flags = (
                            ntlmnegotiate.NegotiateFlags | NTLMSSP_NEGOTIATE_TARGET_INFO
                        )
                        rntlmssp = NTLMSSP_Header(MessageType=2)
                        rntlmchallenge = NTLM_Challenge(NegotiateFlags=neg_flags)

                        # Calculate payload offset (0x38 with Version, 0x30 without)
                        payload_offset = (
                            0x38 if neg_flags & NTLMSSP_NEGOTIATE_VERSION else 0x30
                        )

                        # Set TargetName fields
                        rntlmchallenge.TargetNameFields.Offset = payload_offset
                        rntlmchallenge.TargetNameFields.Len = len(target_name)
                        rntlmchallenge.TargetNameFields.MaxLen = len(target_name)

                        # Set TargetInfo fields (follows TargetName in payload)
                        rntlmchallenge.TargetInfoFields.Offset = payload_offset + len(
                            target_name
                        )
                        rntlmchallenge.TargetInfoFields.Len = len(target_info)
                        rntlmchallenge.TargetInfoFields.MaxLen = len(target_info)

                        rntlmchallenge.ServerChallenge = os.urandom(8)
                        rntlmchallenge.Payload = target_name + target_info
                        rntlmssp = rntlmssp / rntlmchallenge
                        rntlmssp.show()
                        raw = rntlmssp.build()
                        r.SecurityBlob = raw
                        rstatus = 0xC0000016  # STATUS_MORE_PROCESSING_REQUIRED
                elif sb.startswith(b"\x04\x04") or sb.startswith(b"\x05\x04"):
                    # GSSKRB5 CFX wrapping
                    # FIXME is this relevant at all?
                    pass
                else:
                    # (hopefully) the SecurityBlob is prefixed with
                    # * BER encoded identifier
                    # * BER encoded length of the data
                    cls, pc, tag, sb = BER_identifier_dec(sb)
                    _, sb = BER_len_dec(sb)
                    if cls == BER_CLASS_APP and pc > 0 and tag == 0:
                        # NTLM NEGOTIATE
                        #
                        # reply NTML CHALLENGE
                        # SMB_Header.Status = STATUS_MORE_PROCESSING_REQUIRED
                        # SMB_Sessionsetup_ESEC_AndX_Response.SecurityBlob is
                        # \xa1 BER_length NegTokenTarg where
                        # NegTokenTarg.responseToken is NTLM_Header / NTLM_Challenge
                        gssapi = GSSAPI(sb)
                        sb = gssapi.getlayer(Raw).load
                        cls, pc, tag, sb = BER_identifier_dec(sb)
                        _, sb = BER_len_dec(sb)
                        spnego = SPNEGO(sb)
                        spnego.show()
                        sb = spnego.NegotiationToken.mechToken.__str__()
                        try:
                            cls, pc, tag, sb = BER_identifier_dec(sb)
                        except BER_Exception:
                            smblog.warning("BER Exception", exc_info=True)
                            return rp
                        _, sb = BER_len_dec(sb)
                        ntlmssp = NTLMSSP_Header(sb)
                        ntlmssp.show()
                        if ntlmssp.MessageType == 1:
                            r.Action = 0
                            ntlmnegotiate = ntlmssp.getlayer(NTLM_Negotiate)

                            # Build TargetInfo for NTLMv2 authentication
                            target_name, target_info = build_ntlm_target_info(
                                self.config.primary_domain,
                                self.config.server_name,
                            )

                            neg_flags = (
                                ntlmnegotiate.NegotiateFlags
                                | NTLMSSP_NEGOTIATE_TARGET_INFO
                            )
                            rntlmssp = NTLMSSP_Header(MessageType=2)
                            rntlmchallenge = NTLM_Challenge(NegotiateFlags=neg_flags)

                            # Calculate payload offset (0x38 with Version, 0x30 without)
                            payload_offset = (
                                0x38 if neg_flags & NTLMSSP_NEGOTIATE_VERSION else 0x30
                            )

                            # Set TargetName fields
                            rntlmchallenge.TargetNameFields.Offset = payload_offset
                            rntlmchallenge.TargetNameFields.Len = len(target_name)
                            rntlmchallenge.TargetNameFields.MaxLen = len(target_name)

                            # Set TargetInfo fields (follows TargetName in payload)
                            rntlmchallenge.TargetInfoFields.Offset = (
                                payload_offset + len(target_name)
                            )
                            rntlmchallenge.TargetInfoFields.Len = len(target_info)
                            rntlmchallenge.TargetInfoFields.MaxLen = len(target_info)

                            rntlmchallenge.ServerChallenge = os.urandom(8)
                            rntlmchallenge.Payload = target_name + target_info
                            rntlmssp = rntlmssp / rntlmchallenge
                            rntlmssp.show()
                            negtokentarg = NegTokenTarg(
                                negResult=1, supportedMech="1.3.6.1.4.1.311.2.2.10"
                            )
                            negtokentarg.responseToken = rntlmssp.build()
                            negtokentarg.mechListMIC = None
                            raw = negtokentarg.build()
                            r.SecurityBlob = (
                                BER_identifier_enc(BER_CLASS_CON, 1, 1)
                                + BER_len_enc(len(raw))
                                + raw
                            )
                            # STATUS_MORE_PROCESSING_REQUIRED
                            rstatus = 0xC0000016
                    elif cls == BER_CLASS_CON and pc == 1 and tag == 1:
                        # NTLM AUTHENTICATE
                        #
                        # reply
                        # \xa1 BER_length NegTokenTarg('accepted')
                        negtokentarg = NegTokenTarg(sb)
                        negtokentarg.show()
                        ntlmssp = NTLMSSP_Header(negtokentarg.responseToken.val)
                        ntlmssp.show()
                        rnegtokentarg = NegTokenTarg(negResult=0, supportedMech=None)
                        raw = rnegtokentarg.build()
                        # r.SecurityBlob = b'\xa1' + BER_len_enc(len(raw)) + raw
                        r.SecurityBlob = (
                            BER_identifier_enc(BER_CLASS_CON, 1, 1)
                            + BER_len_enc(len(raw))
                            + raw
                        )
            elif p.haslayer(SMB_Sessionsetup_AndX_Request2):
                r = SMB_Sessionsetup_AndX_Response2(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain + "\0",
                )
            else:
                smblog.warning("Unknown Session Setup Type used")

        elif Command == SMB_COM_TREE_CONNECT_ANDX:
            r = SMB_Treeconnect_AndX_Response()
            h = p.getlayer(SMB_Treeconnect_AndX_Request)

            # for SMB_Treeconnect_AndX_Request.Flags = 0x0008
            if h.Flags & 0x08:
                r = SMB_Treeconnect_AndX_Response_Extended()

            # get Path as ascii string
            f, v = h.getfield_and_val("Path")
            Service = f.i2repr(h, v)

            smblog.info(
                "SMB Tree Connect from %s:%d - path: %s",
                self.remote.host,
                self.remote.port,
                Service.rstrip("\x00"),
            )

            # compile Service from the last part of path
            # remove \\
            if Service.startswith("\\\\"):
                Service = Service[1:]
            Service = Service.split("\\")[-1]
            if Service[-1] == "\x00":
                Service = Service[:-1]
            if Service[-1] == "$":
                Service = Service[:-1]
            r.Service = Service + "\x00"

            # specific for NMAP smb-enum-shares.nse support
            if h.Path == b"nmap-share-test\0":
                r = SMB_Treeconnect_AndX_Response2(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain + "\0",
                )
                rstatus = 0xC00000CC  # STATUS_BAD_NETWORK_NAME
            elif h.Path == b"ADMIN$\0" or h.Path == b"C$\0":
                r = SMB_Treeconnect_AndX_Response2(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain + "\0",
                )
                rstatus = 0xC0000022  # STATUS_ACCESS_DENIED
            # support for CVE-2017-7494 Samba SMB RCE
            elif h.Path[-6:] == b"share\0":
                smblog.info("Possible CVE-2017-7494 Samba SMB RCE attempts..")
                r.AndXOffset = 0
                r.Service = "A:\0"
                r.NativeFileSystem = "NTFS\0"
        elif Command == SMB_COM_TREE_DISCONNECT:
            r = SMB_Treedisconnect()
        elif Command == SMB_COM_CLOSE:
            r = p.getlayer(SMB_Close)
            if p.FID in self.fids and self.fids[p.FID] is not None:
                self.fids[p.FID].close()
                fileobj = self.fids[p.FID]
                icd = incident("dionaea.download.complete")
                icd.path = fileobj.name
                icd.url = "smb://" + self.remote.host
                icd.con = self
                icd.report()
                os.unlink(self.fids[p.FID].name)
                del self.fids[p.FID]
                r = SMB_Close_Response()
        elif Command == SMB_COM_LOGOFF_ANDX:
            r = SMB_Logoff_AndX()
        elif Command == SMB_COM_NT_CREATE_ANDX:
            # FIXME return NT_STATUS_OBJECT_NAME_NOT_FOUND=0xc0000034
            # for writes on IPC$
            # this is used to distinguish between file shares and devices by nmap smb-enum-shares
            # requires mapping of TreeConnect ids to names/objects
            r = SMB_NTcreate_AndX_Response()
            h = p.getlayer(SMB_NTcreate_AndX_Request)
            # Log the file/pipe being opened
            f, v = h.getfield_and_val("Filename")
            req_filename = f.i2repr(h, v).rstrip("\x00")
            smblog.info(
                "SMB NT Create from %s:%d - file: %s",
                self.remote.host,
                self.remote.port,
                req_filename,
            )
            r.FID = 0x4000
            while r.FID in self.fids:
                r.FID += 0x200
            if h.FileAttributes & (
                SMB_FA_HIDDEN | SMB_FA_SYSTEM | SMB_FA_ARCHIVE | SMB_FA_NORMAL
            ):
                # if a normal file is requested, provide a file

                dionaea_config = g_dionaea.config().get("dionaea", {})
                download_dir = dionaea_config.get("download.dir")
                download_suffix = dionaea_config.get("download.suffix", ".tmp")
                self.fids[r.FID] = tempfile.NamedTemporaryFile(
                    delete=False,
                    prefix="smb-",
                    suffix=download_suffix,
                    dir=download_dir,
                )

                # get pretty filename
                f, v = h.getfield_and_val("Filename")
                filename = f.i2repr(h, v)
                j = 0
                for j in range(len(filename)):
                    if filename[j] != "\\" and filename[j] != "/":
                        break
                filename = filename[j:]

                i = incident("dionaea.download.offer")
                i.con = self
                i.url = f"smb://{self.remote.host}/{filename}"
                i.report()
                smblog.info("OPEN FILE! %s" % filename)

            elif h.FileAttributes & SMB_FA_DIRECTORY:
                pass
            else:
                self.fids[r.FID] = None
        elif Command == SMB_COM_OPEN_ANDX:
            h = p.getlayer(SMB_Open_AndX_Request)
            r = SMB_Open_AndX_Response()
            r.FID = 0x4000
            while r.FID in self.fids:
                r.FID += 0x200

            dionaea_config = g_dionaea.config().get("dionaea", {})
            download_dir = dionaea_config.get("download.dir")
            download_suffix = dionaea_config.get("download.suffix", ".tmp")

            self.fids[r.FID] = tempfile.NamedTemporaryFile(
                delete=False, prefix="smb-", suffix=download_suffix, dir=download_dir
            )

            # get pretty filename
            f, v = h.getfield_and_val("FileName")
            filename = f.i2repr(h, v)
            j = 0
            for j in range(len(filename)):
                if filename[j] != "\\" and filename[j] != "/":
                    break
            filename = filename[j:]

            i = incident("dionaea.download.offer")
            i.con = self
            i.url = f"smb://{self.remote.host}/{filename}"
            i.report()
            smblog.info("OPEN FILE! %s" % filename)

        elif Command == SMB_COM_ECHO:
            r = p.getlayer(SMB_Header).payload
        elif Command == SMB_COM_WRITE_ANDX:
            r = SMB_Write_AndX_Response()
            h = p.getlayer(SMB_Write_AndX_Request)
            r.CountLow = h.DataLenLow
            if h.FID in self.fids and self.fids[h.FID] is not None:
                smblog.warning("WRITE FILE!")
                self.fids[h.FID].write(h.Data)
            else:
                self.buf += h.Data
                # self.process_dcerpc_packet(p.getlayer(SMB_Write_AndX_Request).Data)
                if len(self.buf) >= 10:
                    # we got the dcerpc header
                    inpacket = DCERPC_Header(self.buf[:10])
                    smblog.debug("got header")
                    inpacket = DCERPC_Header(self.buf)
                    smblog.debug(
                        "FragLen %i len(self.buf) %i"
                        % (inpacket.FragLen, len(self.buf))
                    )
                    if inpacket.FragLen == len(self.buf):
                        outpacket = self.process_dcerpc_packet(self.buf)
                        if outpacket is not None:
                            outpacket.show()
                            self.outbuf = outpacket.build()
                        self.buf = b""
        elif Command == SMB_COM_WRITE:
            h = p.getlayer(SMB_Write_Request)
            if h.FID in self.fids and self.fids[h.FID] is not None:
                smblog.warning("WRITE FILE!")
                self.fids[h.FID].write(h.Data)
            r = SMB_Write_Response(CountOfBytesWritten=h.CountOfBytesToWrite)
        elif Command == SMB_COM_READ_ANDX:
            r = SMB_Read_AndX_Response()
            h = p.getlayer(SMB_Read_AndX_Request)
            # self.outbuf should contain response buffer now
            if not self.outbuf:
                if self.state["stop"]:
                    smblog.debug("drop dead!")
                else:
                    smblog.error("dcerpc processing failed. bailing out.")
                return rp

            rdata = SMB_Data()
            outbuf = self.outbuf
            outbuflen = len(outbuf)
            smblog.debug(
                "MaxCountLow %i len(outbuf) %i readcount %i"
                % (h.MaxCountLow, outbuflen, self.state["readcount"])
            )
            if h.MaxCountLow < outbuflen - self.state["readcount"]:
                rdata.ByteCount = h.MaxCountLow
                newreadcount = self.state["readcount"] + h.MaxCountLow
            else:
                newreadcount = 0
                self.outbuf = None

            rdata.Bytes = outbuf[
                self.state["readcount"] : self.state["readcount"] + h.MaxCountLow
            ]
            rdata.ByteCount = len(rdata.Bytes) + 1
            r.DataLenLow = len(rdata.Bytes)
            smblog.debug(
                "readcount %i len(rdata.Bytes) %i"
                % (self.state["readcount"], len(rdata.Bytes))
            )
            r /= rdata

            self.state["readcount"] = newreadcount

        elif Command == SMB_COM_TRANSACTION:
            h = p.getlayer(SMB_Trans_Request)
            r = SMB_Trans_Response()
            rdata = SMB_Data()

            TransactionName = h.TransactionName
            if isinstance(TransactionName, bytes):
                if smbh.Flags2 & SMB_FLAGS2_UNICODE:
                    TransactionName = TransactionName.decode("utf-16")
                else:
                    TransactionName = TransactionName.decode("ascii")

            if TransactionName[-1] == "\0":
                TransactionName = TransactionName[:-1]

            smblog.info(
                "SMB Transaction from %s:%d - name: %s",
                self.remote.host,
                self.remote.port,
                TransactionName,
            )

            # Check if secondary packets will follow (fragmented transaction)
            if h.TotalParamCount > h.ParamCount or h.TotalDataCount > h.DataCount:
                smblog.info(
                    "SMB Transaction fragmented: params %d/%d, data %d/%d - expecting SECONDARY",
                    h.ParamCount,
                    h.TotalParamCount,
                    h.DataCount,
                    h.TotalDataCount,
                )
                # Store context for SECONDARY packets
                self.trans_name = TransactionName
                self.trans_total_params = h.TotalParamCount
                self.trans_total_data = h.TotalDataCount
                # Initialize with data from primary packet
                self.trans_params = bytes(h.Param) if hasattr(h, "Param") else b""
                self.trans_data = bytes(h.Pad1) if hasattr(h, "Pad1") else b""

            if TransactionName == "\\PIPE\\LANMAN":
                # [MS-RAP].pdf - Remote Administration Protocol
                rapbuf = bytes(h.Param)
                rap = RAP_Request(rapbuf)
                rap.show()
                rout = RAP_Response()
                coff = 0
                comments = []
                if rap.Opcode == RAP_OP_NETSHAREENUM:
                    (InfoLevel, ReceiveBufferSize) = struct.unpack("<HH", rap.Params)
                    smblog.debug(
                        "InfoLevel {} ReceiveBufferSize {}".format(
                            InfoLevel, ReceiveBufferSize
                        )
                    )
                    if InfoLevel == 1:
                        count = len(__shares__)
                        rout.OutParams = struct.pack("<HH", count, count)
                    rout.OutData = b""
                    comments = []
                    for i in __shares__:
                        rout.OutData += struct.pack(
                            "<13sxHHH",
                            i,  # NetworkName
                            # Pad
                            # Type
                            __shares__[i]["type"] & 0xFF,
                            # RemarkOffsetLow
                            coff + len(__shares__) * 20,
                            0x0101,
                        )  # RemarkOffsetHigh
                        comments.append(__shares__[i]["comment"])
                        coff += len(__shares__[i]["comment"]) + 1
                    rout.show()
                outpacket = rout
                self.outbuf = outpacket.build()
                dceplen = len(self.outbuf) + coff

                r.TotalParamCount = 8  # Status|Convert|Count|Available
                r.TotalDataCount = dceplen

                r.ParamCount = 8  # Status|Convert|Count|Available
                r.ParamOffset = 56

                r.DataCount = dceplen
                r.DataOffset = 64

                rdata.ByteCount = dceplen
                rdata.Bytes = self.outbuf + b"".join(
                    c.encode("ascii") + b"\x00" for c in comments
                )

            elif TransactionName == "\\PIPE\\":
                setup_code = socket.htons(h.Setup[0]) if h.Setup else 0
                smblog.info(
                    "SMB Transaction \\PIPE\\ setup code: 0x%04x",
                    setup_code,
                )
                if setup_code == TRANS_NMPIPE_TRANSACT:
                    outpacket = self.process_dcerpc_packet(p.getlayer(DCERPC_Header))

                    if not outpacket:
                        if self.state["stop"]:
                            smblog.debug("drop dead!")
                        else:
                            smblog.error("dcerpc processing failed. bailing out.")
                        return rp
                    self.outbuf = outpacket.build()
                    dceplen = len(self.outbuf)

                    r.TotalDataCount = dceplen
                    r.DataCount = dceplen

                    rdata.ByteCount = dceplen
                    rdata.Bytes = self.outbuf

                elif setup_code == TRANS_NMPIPE_PEEK:
                    SetupCount = h.SetupCount
                    if SetupCount > 0:
                        smblog.info("MS17-010 - SMB RCE exploit scanning..")
                        r = SMB_Trans_Response_Simple()
                        # returned #STATUS_INSUFF_SERVER_RESOURCE as we not being patched
                        rstatus = 0xC0000205  # STATUS_INSUFF_SERVER_RESOURCES

            r /= rdata
        elif Command == SMB_COM_TRANSACTION2:
            h = p.getlayer(SMB_Trans2_Request)
            if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                # DoublePulsar v1 (WannaCry): opcodes encoded via calculate_doublepulsar_opcode()
                # https://zerosum0x0.blogspot.sg/2017/04/doublepulsar-initial-smb-backdoor-ring.html
                #   0x23 = ping, 0xc8 = exec, 0x77 = kill
                # DoublePulsar v2.0 (Petya/NotPetya): raw opcodes in Timeout field
                # https://blog.checkpoint.com/research/brokers-shadows-part-2-analyzing-petyas-doublepulsarv2-0-backdoor/
                #   0xf0 = check installed, 0xf1 = uninstall, 0xf2 = exec

                # Log opcode only on first chunk to avoid spam
                if len(self.buf2) == 0:
                    # Check for v2.0 first (raw opcode in low byte of Timeout)
                    raw_op = h.Timeout & 0xFF
                    v2_oplist = {0xF0: "check", 0xF1: "uninstall", 0xF2: "exec"}
                    if raw_op in v2_oplist:
                        smblog.info(
                            f"DoublePulsar v2.0 opcode: 0x{raw_op:02x} command: {v2_oplist[raw_op]}"
                        )
                    else:
                        # Fall back to v1 opcode calculation
                        op = calculate_doublepulsar_opcode(h.Timeout)
                        op2 = hex(op)[-2:]
                        v1_oplist = [("23", "ping"), ("c8", "exec"), ("77", "kill")]
                        matched = False
                        for fid, command in v1_oplist:
                            if op2 == fid:
                                smblog.info(
                                    f"DoublePulsar v1 opcode: {op2} command: {command}"
                                )
                                matched = True
                                break
                        if not matched:
                            smblog.info(
                                "DoublePulsar unknown opcode: 0x%02x (raw) / 0x%s (v1 calc)",
                                raw_op,
                                op2,
                            )

                # make sure the payload size not larger than 10MB
                if len(self.buf2) > 10485760:
                    self.buf2 = b""
                elif h.DataCount == 4096:
                    # Full chunk - accumulate (first or middle chunk)
                    self.buf2 = self.buf2 + h.Data
                    smblog.debug(
                        "DoublePulsar chunk: %d bytes, total accumulated: %d",
                        h.DataCount,
                        len(self.buf2),
                    )
                    # Send acknowledgement response for intermediate chunks
                    r = SMB_Trans2_Response()
                    rstatus = 0x00000000  # STATUS_SUCCESS
                elif h.DataCount > 0 and h.DataCount < 4096:
                    # Final chunk - accumulate, respond, process on disconnect
                    self.buf2 = self.buf2 + h.Data
                    smblog.debug(
                        "DoublePulsar final chunk: %d bytes, total: %d",
                        h.DataCount,
                        len(self.buf2),
                    )
                    r = SMB_Trans2_Response()
                    rstatus = 0x00000000  # STATUS_SUCCESS
                else:
                    # No data in this request
                    r = SMB_Trans2_Response()
                    rstatus = 0xC0000002  # STATUS_NOT_IMPLEMENTED
            elif h.Setup[0] == SMB_TRANS2_FIND_FIRST2:
                r = SMB_Trans2_FIND_FIRST2_Response()
            elif h.Setup[0] == SMB_TRANS2_QUERY_FS_INFORMATION:
                # Get the information level from Params (first 2 bytes)
                info_level = 0
                if len(h.Param) >= 2:
                    info_level = h.Param[0] | (h.Param[1] << 8)

                smblog.debug(
                    "TRANS2_QUERY_FS_INFORMATION: level=0x%04x from %s:%d",
                    info_level,
                    self.remote.host,
                    self.remote.port,
                )

                if info_level == 0x0103:  # SMB_QUERY_FS_SIZE_INFO
                    # FileFsSizeInformation structure (24 bytes)
                    # TotalAllocationUnits (8), TotalFreeAllocationUnits (8),
                    # SectorsPerAllocationUnit (4), BytesPerSector (4)
                    data = struct.pack(
                        "<QQII",
                        1024 * 1024,  # TotalAllocationUnits (1TB with 1MB units)
                        512 * 1024,  # TotalFreeAllocationUnits (512GB free)
                        8,  # SectorsPerAllocationUnit
                        512,  # BytesPerSector
                    )
                    r = SMB_Trans2_QUERY_FS_INFO_Response(Data=data)
                elif info_level == 0x0105:  # SMB_QUERY_FS_ATTRIBUTE_INFO
                    # FileFsAttributeInformation structure
                    # FileSystemAttributes (4), MaxFileNameLength (4),
                    # FileSystemNameLength (4), FileSystemName (variable)
                    fs_name = "NTFS".encode("utf-16-le")
                    data = struct.pack("<III", 0x0000000F, 255, len(fs_name)) + fs_name
                    r = SMB_Trans2_QUERY_FS_INFO_Response(Data=data)
                elif info_level == 0x0102:  # SMB_QUERY_FS_VOLUME_INFO
                    # FileFsVolumeInformation structure
                    # VolumeCreationTime (8), VolumeSerialNumber (4),
                    # VolumeLabelLength (4), SupportsObjects (1), Reserved (1),
                    # VolumeLabel (variable)
                    # TODO: make volume label configurable
                    vol_label = self.config.server_name.encode("utf-16-le")
                    data = (
                        struct.pack("<QIIBB", 0, 0x12345678, len(vol_label), 0, 0)
                        + vol_label
                    )
                    r = SMB_Trans2_QUERY_FS_INFO_Response(Data=data)
                else:
                    smblog.warning(
                        "Unsupported FS info level: 0x%04x from %s:%d",
                        info_level,
                        self.remote.host,
                        self.remote.port,
                    )
                    r = SMB_Trans2_Response()
                    rstatus = 0xC0000002  # STATUS_NOT_IMPLEMENTED
            else:
                subcmd = h.Setup[0]
                subcmd_name = SMB_Trans2_Commands.get(subcmd, "UNKNOWN")
                smblog.warning(
                    "Unsupported Transaction2 subcommand: %s (0x%02x)",
                    subcmd_name,
                    subcmd,
                )
                r = SMB_Trans2_Response()

        elif Command == SMB_COM_DELETE:
            h = p.getlayer(SMB_Delete_Request)
            r = SMB_Delete_Response()
        elif Command == SMB_COM_TRANSACTION2_SECONDARY:
            h = p.getlayer(SMB_Trans2_Secondary_Request)
            # TODO: need some extra works
            pass
        elif Command == SMB_COM_NT_TRANSACT:
            h = p.getlayer(SMB_NT_Trans_Request)
            r = SMB_NT_Trans_Response()
            rstatus = 0x00000000  # STATUS_SUCCESS
        elif Command == SMB_COM_QUERY_INFORMATION_DISK:
            # Return fake disk information (same values as TRANS2_QUERY_FS_SIZE_INFO)
            # Values fit in 16-bit fields, so use smaller units
            r = SMB_Query_Information_Disk_Response(
                TotalUnits=65535,  # ~32GB with 512KB units
                BlocksPerUnit=1024,  # Sectors per unit
                BlockSize=512,  # Bytes per sector
                FreeUnits=32768,  # ~16GB free
            )
            rstatus = 0x00000000  # STATUS_SUCCESS
        elif Command == SMB_COM_TRANSACTION_SECONDARY:
            h = p.getlayer(SMB_Trans_Secondary_Request)
            smblog.info(
                "SMB Transaction Secondary from %s:%d - name: %s, params: %d/%d, data: %d/%d",
                self.remote.host,
                self.remote.port,
                self.trans_name or "(unknown)",
                h.ParamCount,
                h.TotalParamCount,
                h.DataCount,
                h.TotalDataCount,
            )

            # Store expected totals from first secondary packet
            if self.trans_total_params == 0 and self.trans_total_data == 0:
                self.trans_total_params = h.TotalParamCount
                self.trans_total_data = h.TotalDataCount

            # Accumulate params at displacement offset
            if h.ParamCount > 0:
                disp = h.ParamDisplacement
                # Extend buffer if needed
                if disp + h.ParamCount > len(self.trans_params):
                    self.trans_params = self.trans_params.ljust(
                        disp + h.ParamCount, b"\x00"
                    )
                # Copy data at displacement
                params_bytes = bytes(h.Params) if hasattr(h, "Params") else b""
                self.trans_params = (
                    self.trans_params[:disp]
                    + params_bytes[: h.ParamCount]
                    + self.trans_params[disp + h.ParamCount :]
                )

            # Accumulate data at displacement offset
            if h.DataCount > 0:
                disp = h.DataDisplacement
                # Extend buffer if needed
                if disp + h.DataCount > len(self.trans_data):
                    self.trans_data = self.trans_data.ljust(disp + h.DataCount, b"\x00")
                # Copy data at displacement
                data_bytes = bytes(h.Data) if hasattr(h, "Data") else b""
                self.trans_data = (
                    self.trans_data[:disp]
                    + data_bytes[: h.DataCount]
                    + self.trans_data[disp + h.DataCount :]
                )

            smblog.debug(
                "Transaction Secondary accumulated: params %d/%d, data %d/%d",
                len(self.trans_params),
                self.trans_total_params,
                len(self.trans_data),
                self.trans_total_data,
            )

            # Check if complete
            if (
                len(self.trans_params) >= self.trans_total_params
                and len(self.trans_data) >= self.trans_total_data
            ):
                # Identify data type
                data_type = "unknown"
                if self.trans_data:
                    if len(self.trans_data) >= 2 and self.trans_data[0] == 0x05:
                        # DCE/RPC: version=5, version_minor, packet_type
                        pkt_types = {
                            0: "request",
                            2: "response",
                            11: "bind",
                            12: "bind_ack",
                            14: "alter_context",
                        }
                        pkt_type = (
                            self.trans_data[2] if len(self.trans_data) > 2 else -1
                        )
                        data_type = (
                            f"DCE/RPC {pkt_types.get(pkt_type, f'type={pkt_type}')}"
                        )
                    elif self.trans_data[:2] == b"MZ":
                        data_type = "PE executable"
                    elif self.trans_data[:4] == b"\x7fELF":
                        data_type = "ELF executable"

                smblog.info(
                    "Transaction Secondary complete: name=%s, %d param bytes, %d data bytes, type=%s",
                    self.trans_name or "(unknown)",
                    len(self.trans_params),
                    len(self.trans_data),
                    data_type,
                )
                # Log hex dump for analysis
                if self.trans_data:
                    smblog.info(
                        "Transaction data (hex, first 256 bytes): %s",
                        self.trans_data[:256].hex(),
                    )
                # Reset accumulators
                self.trans_params = b""
                self.trans_data = b""
                self.trans_total_params = 0
                self.trans_total_data = 0
                self.trans_name = ""

            # Send interim response
            r = SMB_Trans_Response_Simple()
            rstatus = 0x00000000  # STATUS_SUCCESS
        else:
            cmd_name = SMB_Commands.get(Command, "UNKNOWN")
            smblog.warning("Unsupported SMB command: %s (0x%02x)", cmd_name, Command)
            # Return error response for unsupported commands
            r = SMB_Trans_Response_Simple()
            rstatus = 0xC0000002  # STATUS_NOT_IMPLEMENTED

        if r:
            smbh = SMB_Header(Status=rstatus)
            # For error responses (non-zero status), echo back the original command
            smbh.Command = Command if rstatus != 0 else r.smb_cmd
            smbh.Flags2 = p.getlayer(SMB_Header).Flags2
            # smbh.Flags2 = p.getlayer(SMB_Header).Flags2 & ~SMB_FLAGS2_EXT_SEC
            smbh.MID = p.getlayer(SMB_Header).MID
            smbh.PID = p.getlayer(SMB_Header).PID
            # DoublePulsar PING response: MID+16 signals success, Signature encodes XOR key
            # Upper 32 bits of Signature: 0 = x86, non-zero = x64
            if Command == SMB_COM_TRANSACTION2:
                h = p.getlayer(SMB_Trans2_Request)
                if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                    smbh.MID = p.getlayer(SMB_Header).MID + 16
                    arch_indicator = 0x1 if self.config.os_arch == 64 else 0x0
                    smbh.Signature = smbd.doublepulsar_signature | (
                        arch_indicator << 32
                    )
            rp = NBTSession() / smbh / r

        if Command in SMB_Commands:
            self.state["lastcmd"] = SMB_Commands[p.getlayer(SMB_Header).Command]
        else:
            self.state["lastcmd"] = "UNKNOWN"
        return rp

    def process_dcerpc_packet(self, buf):
        if not isinstance(buf, DCERPC_Header):
            smblog.debug("got buf, make DCERPC_Header")
            dcep = DCERPC_Header(buf)
        else:
            dcep = buf

        outbuf = None

        smblog.debug("data")
        try:
            dcep.show()
        except Exception:
            return None
        if dcep.AuthLen > 0:
            # print(dcep.getlayer(Raw).underlayer.load)
            # dcep.getlayer(Raw).underlayer.decode_payload_as(DCERPC_Auth_Verfier)
            dcep.show()

        if dcep.PacketType == 11:  # bind
            try:
                ctx_items = dcep.CtxItems
                if ctx_items is None:
                    raise AttributeError("CtxItems is None")
            except AttributeError:
                smblog.warning("Malformed DCERPC bind packet: missing CtxItems")
                return None
            outbuf = DCERPC_Header() / DCERPC_Bind_Ack()
            outbuf.CallID = dcep.CallID
            c = 0
            outbuf.CtxItems = [DCERPC_Ack_CtxItem() for i in range(len(dcep.CtxItems))]
            while c < len(dcep.CtxItems):  # isinstance(tmp, DCERPC_CtxItem):
                tmp = dcep.CtxItems[c]
                ctxitem = outbuf.CtxItems[c]
                service_uuid = UUID(bytes_le=tmp.UUID)
                transfersyntax_uuid = UUID(bytes_le=tmp.TransferSyntax)
                ctxitem.TransferSyntax = tmp.TransferSyntax  # [:16]
                ctxitem.TransferSyntaxVersion = tmp.TransferSyntaxVersion
                # Check for supported transfer syntaxes (NDR32 or NDR64)
                syntax_str = str(transfersyntax_uuid)
                if syntax_str == NDR32_UUID:
                    pointer_size = 32
                elif syntax_str == NDR64_UUID:
                    pointer_size = 64
                else:
                    pointer_size = None

                if pointer_size is not None:
                    if service_uuid.hex in registered_services:
                        service = registered_services[service_uuid.hex]
                        smblog.info(
                            "Found a registered UUID (%s). Accepting Bind for %s (NDR%d)"
                            % (service_uuid, service.__class__.__name__, pointer_size)
                        )
                        self.state["uuid"] = service_uuid.hex
                        self.state["pointer_size"] = pointer_size
                        # Copy Transfer Syntax to CtxItem
                        ctxitem.AckResult = 0
                        ctxitem.AckReason = 0
                    else:
                        smblog.warning(
                            "Attempt to register %s failed, UUID does not exist or is not implemented",
                            service_uuid,
                        )
                else:
                    smblog.warning(
                        "Attempt to register %s failed, TransferSyntax %s is unknown",
                        service_uuid,
                        transfersyntax_uuid,
                    )
                i = incident("dionaea.modules.python.smb.dcerpc.bind")
                i.con = self
                # Include service name if known
                if service_uuid.hex in registered_services:
                    service_name = registered_services[
                        service_uuid.hex
                    ].__class__.__name__
                    i.uuid = f"{service_uuid} ({service_name})"
                else:
                    i.uuid = str(service_uuid)
                # Include transfer syntax name if known
                syntax_name = TRANSFER_SYNTAX_NAMES.get(syntax_str)
                if syntax_name:
                    i.transfersyntax = f"{transfersyntax_uuid} ({syntax_name})"
                else:
                    i.transfersyntax = str(transfersyntax_uuid)
                i.report()
                c += 1
            outbuf.NumCtxItems = c
            outbuf.FragLen = len(outbuf.build())
            smblog.debug("dce reply")
            outbuf.show()
        elif dcep.PacketType == 0:  # request
            resp = None
            if "uuid" in self.state:
                service = registered_services[self.state["uuid"]]
                resp = service.processrequest(service, self, dcep.OpNum, dcep)
                i = incident("dionaea.modules.python.smb.dcerpc.request")
                i.con = self
                service_uuid = UUID(bytes=bytes.fromhex(self.state["uuid"]))
                i.uuid = f"{service_uuid} ({service.__class__.__name__})"
                i.opnum = dcep.OpNum
                i.stub_data = dcep.build()
                i.report()
            else:
                smblog.info("DCERPC Request without pending action")
            if not resp:
                self.state["stop"] = True
            outbuf = resp
        else:
            # unknown DCERPC packet -> logcrit and bail out.
            smblog.error("unknown DCERPC packet. bailing out.")
        return outbuf

    def handle_timeout_idle(self):
        return False

    def handle_disconnect(self):
        # Process any accumulated DoublePulsar payload on disconnect
        if len(self.buf2) > 0:
            smblog.info(
                "Connection closed with %d bytes buffered, processing",
                len(self.buf2),
            )
            self._process_doublepulsar_payload()

        for fid in list(self.fids.values()):
            if fid is not None:
                fid.close()
                os.unlink(fid.name)
        self.fids.clear()
        return 0


class epmapper(smbd):
    def __init__(self):
        connection.__init__(self, "tcp")
        smbd.__init__(self)

    def handle_io_in(self, data):
        # DCERPC header is 16 bytes minimum
        if len(data) < 16:
            return 0  # Wait for more data

        try:
            p = DCERPC_Header(data)
        except Exception as e:
            smblog.warning("DCERPC packet parsing failed: %s", str(e))
            return len(data)

        # Validate DCERPC version - must be 5.x
        if p.Version != 5:
            smblog.warning("Invalid DCERPC version: %d.%d", p.Version, p.VersionMinor)
            return len(data)

        # Validate FragLen - minimum is 16 (header size), max sanity check
        if p.FragLen < 16 or p.FragLen > 65535:
            smblog.warning("Invalid DCERPC FragLen: %d", p.FragLen)
            return len(data)

        if len(data) < p.FragLen:
            smblog.debug(
                "epmapper waiting for more data (%d/%d bytes)", len(data), p.FragLen
            )
            return 0

        smblog.debug("packet: %s" % p.summary())

        r = self.process_dcerpc_packet(p)

        if self.state["stop"]:
            smblog.info("faint death.")
            return len(data)

        if not r or r is None:
            return len(data)

        smblog.debug("response: %s" % r.summary())
        r.show()
        self.send(r.build())

        if p.haslayer(Raw):
            smblog.debug("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

        return len(data)


services = inspect.getmembers(rpcservices, inspect.isclass)
for name, servicecls in services:
    if not name == "RPCService" and issubclass(servicecls, rpcservices.RPCService):
        register_rpc_service(servicecls())

# Log the generated DoublePulsar key at startup
smblog.info(
    "DoublePulsar signature: 0x%08x, XOR key: 0x%08x",
    smbd.doublepulsar_signature,
    smbd.doublepulsar_xor_key,
)
