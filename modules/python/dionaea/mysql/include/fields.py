# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2011 Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.smb.include.fieldtypes import IntField, Field, StrField
import struct

class Int24Field(IntField):
    def __init__(self, name, default):
        IntField.__init__(self,name,default)
    def i2len(self, pkt, i):
        return 3
    def i2m(self, pkt, y):
        return struct.pack("<BBB", y&0xff, (y&0xff00) >> 8, (y&0xff0000) >> 16)
    def m2i(self, pkt, x):
        (lo,m,h) = struct.unpack("<BBB", x[:3])
        return h * 2**16 + m * 2**8 + lo
    def addfield(self, pkt, s, val):
        m = self.i2m(pkt, val)
        return s+m
    def getfield(self, pkt, d):
        return d[3:],self.m2i(pkt, d)
    def size(self, pkt, val):
        return 3

class LengthCodedIntField(IntField):
    def __init__(self, name, default):
        Field.__init__(self,name,default,fmt="H")
    def i2len(self, pkt, i):
        return len(self.i2m(pkt,i))
    def i2m(self, pkt, y):
        if y is None:
            y = 0
        encoded = b''
        if y < 250:
            encoded = struct.pack("<B", y)
        elif y < 2**16:
            encoded = struct.pack("<BH", 252, y)
        elif y < 2**32:
            encoded = struct.pack("<BI", 253, y)
        else:
            encoded = struct.pack("<BQ", 254, y)
        return encoded
    def m2i(self, pkt, x):
        (length,o,s) = self._los(x)
        return length
    def addfield(self, pkt, s, val):
        m = self.i2m(pkt, val)
        return s+m
    def getfield(self, pkt, d):
        (length,o,s) = self._los(d)
        return d[s+o:],self.m2i(pkt, d)
    def size(self, pkt, val):
        return len(self.i2m(pkt, val))
    def _los(self, d):
        length = d[0]
        o = 1
        s = 1
        if length<=250 or length == 251:
            o = 0
        elif length == 252:
            s = 2
            (length,) = struct.unpack("<H", d[o:o+s])
        elif length == 253:
            s = 4
            (length,) = struct.unpack("<I", d[o:o+s])
        elif length == 254:
            s = 8
            (length,) = struct.unpack("<Q", d[o:o+s])
        return (length,o,s)

class LengthCodedBinaryField(StrField):
    def __init__(self, name, default):
        Field.__init__(self,name,default,fmt="H")
    def i2len(self, pkt, i):
        return len(self.i2m(pkt,i))
    def i2m(self, pkt, x):
        if x is None:
            y = None
        else:
            if isinstance(x, str):
                x = x.encode('ascii')
            elif not isinstance(x, bytes):
                x = str(x).encode('ascii')
            y=len(x)

        encoded = b''
        if y is None:
            encoded = struct.pack("<B", 251)
            x = b''
        elif y == 0:
            encoded = struct.pack("<B", y)
            x = b''
        elif y > 0 and y < 250:
            encoded = struct.pack("<B", y)
        elif y < 2**16:
            encoded = struct.pack("<BH", 252, y)
        elif y < 2**32:
            encoded = struct.pack("<BI", 253, y)
        else:
            encoded = struct.pack("<BQ", 254, y)
        return encoded+x
    def m2i(self, pkt, x):
        (length,o,s) = self._los(x)
        return x[o+s:o+s+length]
    def addfield(self, pkt, s, val):
        m = self.i2m(pkt, val)
        return s+m
    def getfield(self, pkt, d):
        (length,o,s) = self._los(d)
        return d[s+o+length:],self.m2i(pkt, d)
    def size(self, pkt, val):
        return len(self.i2m(pkt, val))
    def _los(self, d):
        length = d[0]
        o = 1
        s = 1
        if length<=250 or length == 251:
            o = 0
        elif length == 252:
            s = 2
            (length,) = struct.unpack("<H", d[o:o+s])
        elif length == 253:
            s = 4
            (length,) = struct.unpack("<I", d[o:o+s])
        elif length == 254:
            s = 8
            (length,) = struct.unpack("<Q", d[o:o+s])
        return (length,o,s)
