# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
# SPDX-FileCopyrightText: 2010 Markus Koetter & Tan Kean Siong
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Implements (a subset of) NDR -- Network Data Representation.

    http://www.opengroup.org/onlinepubs/9629399/chap14.htm

    Supports both NDR (32-bit) and NDR64 (64-bit) transfer syntaxes.
    NDR:   8a885d04-1ceb-11c9-9fe8-08002b104860
    NDR64: 6cb71c2c-9812-4540-0300-000000000000
"""

from __future__ import annotations

import struct
from io import BytesIO
from typing import Literal

__all__ = ["Error", "Packer", "Unpacker"]

# Transfer syntax UUIDs
NDR32_UUID = '8a885d04-1ceb-11c9-9fe8-08002b104860'
NDR64_UUID = '6cb71c2c-9812-4540-0300-000000000000'

# exceptions
class Error(Exception):
    """Exception class for this module. Use:

    except ndrlib.Error, var:
            # var has the Error instance for the exception

    Public ivars:
            msg -- contains the message

    """
    def __init__(self, msg: str) -> None:
        self.msg = msg
    def __repr__(self) -> str:
        return repr(self.msg)
    def __str__(self) -> str:
        return str(self.msg)


class Unpacker:
    """Unpacks basic data representations from the given buffer."""

    def __init__(
        self,
        data: bytes,
        integer: Literal['le', 'be'] = 'le',
        char: str = 'ascii',
        floating: str = 'IEEE',
        pointer_size: Literal[32, 64] = 32
    ) -> None:
        self.pointer_size = pointer_size
        self.reset(data)

    def reset(self, data: bytes) -> None:
        self.__buf = data
        self.__pos = 0

    def get_position(self) -> int:
        return self.__pos

    def set_position(self, position: int) -> None:
        self.__pos = position

    def get_buffer(self) -> bytes:
        return self.__buf

    def done(self) -> None:
        if self.__pos < len(self.__buf):
            raise Error('unextracted data remains')

    def unpack_small(self) -> int:
        i = self.__pos
        self.__pos = j = i+1
        data = self.__buf[i:j]
        if len(data) < 1:
            raise EOFError
        x = struct.unpack('<B', data)[0]
        try:
            return int(x)
        except OverflowError:
            return x

    def unpack_short(self) -> int:
        self.__pos += self.__pos % 2
        i = self.__pos
        self.__pos = j = i+2
        data = self.__buf[i:j]
        if len(data) < 2:
            raise EOFError
        return struct.unpack('<H', data)[0]

    def unpack_long(self) -> int:
        self.__pos += self.__pos % 4
        i = self.__pos
        self.__pos = j = i+4
        data = self.__buf[i:j]
        if len(data) < 4:
            raise EOFError
        return struct.unpack('<L', data)[0]

    def unpack_hyper(self) -> int:
        align = self.__pos % 8
        if align > 0:
            self.__pos += 8 - align
        i = self.__pos
        self.__pos = j = i+8
        data = self.__buf[i:j]
        if len(data) < 8:
            raise EOFError
        return struct.unpack('<Q', data)[0]

    def unpack_bool(self) -> bool:
        return bool(self.unpack_long())

    def unpack_pointer(self) -> int:
        if self.pointer_size == 64:
            return self.unpack_hyper()
        return self.unpack_long()

    def unpack_string(self, width: int = 16) -> bytes:
        self.unpack_long()
        self.unpack_long()
        ac = self.unpack_long()
        #print("mc %i ac %i off %i" % ( mc, ac, off))
        i = self.__pos
        self.__pos = j = i+(ac*int(width/8))
        data = self.__buf[i:j]
        if len(data) < ac:
            raise EOFError
        return data

    def unpack_raw(self, length: int) -> bytes:
        data = self.__buf[self.__pos:self.__pos+length]
        self.__pos = self.__pos + length
        return data


class Packer:
    """Pack various data representations into a buffer."""

    def __init__(
        self,
        integer: Literal['le', 'be'] = 'le',
        char: str = 'ascii',
        floating: str = 'IEEE',
        pointer_size: Literal[32, 64] = 32
    ) -> None:
        self.reset()
        self.integer = integer
        self.pointer_size = pointer_size

    def reset(self) -> None:
        self.__buf = BytesIO()

    def get_buffer(self) -> bytes:
        return self.__buf.getvalue()

    def pack_small(self, x: int) -> None:
        """8-bit integer"""
        self.__buf.write(struct.pack('<B', x))

    def pack_short(self, x: int) -> None:
        """16-bit integer"""
        if self.__buf.tell() % 2 > 0:
            self.__buf.write(b'\0')
        if self.integer == 'le':
            self.__buf.write(struct.pack('<H', x))
        else:
            self.__buf.write(struct.pack('>H', x))

    def pack_long(self, x: int) -> None:
        """32-bit integer"""
        align = self.__buf.tell() % 4
        if align > 0:
            self.__buf.write(b'\0'*align)
        if self.integer == 'le':
            self.__buf.write(struct.pack('<L', x))
        else:
            self.__buf.write(struct.pack('>L', x))

    def pack_long_signed(self, x: int) -> None:
        """32-bit signed integer"""
        align = self.__buf.tell() % 4
        if align > 0:
            self.__buf.write(b'\0'*align)
        if self.integer == 'le':
            self.__buf.write(struct.pack('<l', x))
        else:
            self.__buf.write(struct.pack('>l', x))

    def pack_hyper(self, x: int) -> None:
        """64-bit integer"""
        align = self.__buf.tell() % 8
        if align > 0:
            self.__buf.write(b'\0'*align)
        if self.integer == 'le':
            self.__buf.write(struct.pack('<Q', x))
        else:
            self.__buf.write(struct.pack('>Q', x))

    def pack_pointer(self, x: int) -> None:
        if self.pointer_size == 64:
            self.pack_hyper(x)
        else:
            self.pack_long(x)

    def pack_bool(self, x: bool) -> None:
        if x:
            self.__buf.write(b'\0\0\0\1')
        else:
            self.__buf.write(b'\0\0\0\0')

    def pack_string(self, s: bytes, offset: int = 0, width: int = 16) -> None:
        """Pack string with different maxcount and actualcount."""
        x = int(len(s)/(width/8))
        if (x % 8 == 0):
            maxcount = x
        else:
            maxcount = (int(x/8) + 1)*8
        self.pack_long(maxcount)
        self.pack_long(offset)
        self.pack_long(x)
        self.__buf.write(s)

    def pack_string_fix(self, s: bytes, offset: int = 0, width: int = 16) -> None:
        """Pack string with same maxcount and actualcount."""
        x = int(len(s)/(width/8))
        self.pack_long(x)
        self.pack_long(offset)
        self.pack_long(x)
        self.__buf.write(s)

    def pack_raw(self, s: bytes) -> None:
        self.__buf.write(s)

    def pack_rpc_unicode_string(self, s: bytes) -> None:
        """Pack only the maxcount and actualcount of rpc unicode string."""
        Length = MaximumLength = len(s)
        if Length % 8:
            MaximumLength = (int(Length/8) + 1)*8

        self.pack_short(Length*2)
        self.pack_short(MaximumLength*2)
