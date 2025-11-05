# This file was part of Scapy and is now part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 20??-2010 Philippe Biondi <phil@secdev.org>
# SPDX-FileCopyrightText: 2010 Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-only
#
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

from typing import Any
from .packet import Packet

class ASN1_Packet(Packet):
    ASN1_root: Any = None
    ASN1_codec: Any = None

    def init_fields(self) -> None:
        flist = self.ASN1_root.get_fields_list()
        self.do_init_fields(flist)
        self.fields_desc = flist

    def do_build(self) -> bytes:
        return self.ASN1_root.build(self)

    def do_dissect(self, x: bytes) -> bytes:
        return self.ASN1_root.dissect(self, x)
