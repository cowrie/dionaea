# This file was part of Scapy and is now part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 20??-2010 Philippe Biondi <phil@secdev.org>
# SPDX-FileCopyrightText: 2009  Paul Baecher & Markus Koetter & Mark Schloesser
# SPDX-FileCopyrightText: 2010 Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-only
#
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

import random
import re
import socket
import warnings


class VolatileValue:
    def __repr__(self):
        return "<%s>" % self.__class__.__name__
    def __getattr__(self, attr):
        if attr == "__setstate__":
            raise AttributeError(attr)
        return getattr(self._fix(),attr)
    def _fix(self):
        return None

class Gen:
    def __iter__(self):
        return iter([])


class Net(Gen):
    """Generate a list of IPs from a network address or a name"""
    name = "ip"
    ipaddress = re.compile(
        r"^(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)(/[0-3]?[0-9])?$")
    def __init__(self, net):
        self.repr=net

        tmp=net.split('/')+["32"]
        if not self.ipaddress.match(net):
            tmp[0]=socket.gethostbyname(tmp[0])
        netmask = int(tmp[1])

        def parse_digit(a,netmask):
            netmask = min(8,max(netmask,0))
            if a == "*":
                a = (0,256)
            elif a.find("-") >= 0:
                x,y = list(map(int,a.split("-")))
                if x > y:
                    y = x
                a = (
                    x &  (0xff<<netmask) , max(y, (x | (0xff>>(8-netmask))))+1)
            else:
                a = (int(a) & (0xff<<netmask),(int(a) | (0xff>>(8-netmask)))+1)
            return a

        self.parsed = list(map(lambda x,y: parse_digit(x,y), tmp[0].split(
            "."), list(map(lambda x,nm=netmask: x-nm, (8,16,24,32)))))

    def __iter__(self):
        for d in range(*self.parsed[3]):
            for c in range(*self.parsed[2]):
                for b in range(*self.parsed[1]):
                    for a in range(*self.parsed[0]):
                        yield "%i.%i.%i.%i" % (a,b,c,d)
    def choice(self):
        ip = []
        for v in self.parsed:
            ip.append(str(random.randint(v[0],v[1]-1)))
        return ".".join(ip)

    def __repr__(self):
        return "Net(%r)" % self.repr


class SetGen(Gen):
    def __init__(self, set, _iterpacket=1):
        self._iterpacket=_iterpacket
        if isinstance(set, list):
            self.set = set
        elif isinstance(set, BasePacketList):
            self.set = list(set)
        else:
            self.set = [set]
    def transf(self, element):
        return element
    def __iter__(self):
        for i in self.set:
            if isinstance(i, tuple) and len(i) == 2 and isinstance(i[0], int) and isinstance(i[1], int):
                if  (i[0] <= i[1]):
                    j=i[0]
                    while j <= i[1]:
                        yield j
                        j += 1
            elif isinstance(i, Gen) and (self._iterpacket or not isinstance(i,BasePacket)):
                for j in i:
                    yield j
            else:
                yield i
    def __repr__(self):
        return "<SetGen %s>" % self.set.__repr__()

class BasePacket(Gen):
    pass

class BasePacketList:
    pass

def lhex(x):
    if isinstance(x, int):
        return hex(x)
    elif isinstance(x, tuple):
        return "(%s)" % ", ".join(map(lhex, x))
    elif isinstance(x, list):
        return "[%s]" % ", ".join(map(lhex, x))
    else:
        return x

#########################
#### Enum management ####
#########################

class EnumElement:
    _value=None
    def __init__(self, key, value):
        self._key = key
        self._value = value
    def __repr__(self):
        return "<{} {}[{!r}]>".format(self.__dict__.get("_name", self.__class__.__name__), self._key, self._value)
    def __getattr__(self, attr):
        return getattr(self._value, attr)
    def __int__(self):
        return self._value
    def __str__(self):
        return self._key
    def __eq__(self, other):
        return self._value == int(other)


class Enum_metaclass(type):
    element_class = EnumElement
    def __new__(cls, name, bases, dct):
        rdict={}
        for k,v in dct.items():
            if isinstance(v, int):
                v = cls.element_class(k,v)
                dct[k] = v
                rdict[type(v)] = k
        dct["__rdict__"] = rdict
        return super().__new__(cls, name, bases, dct)
    def __getitem__(self, attr):
        return self.__rdict__[attr]
    def __contains__(self, val):
        return val in self.__rdict__
    def get(self, attr, val=None):
        return self._rdict__.get(attr, val)
    def __repr__(self):
        return "<%s>" % self.__dict__.get("name", self.__name__)


# Utility functions for MAC address conversion (from scapy)
def mac2str(mac):
    """Convert MAC address from human readable format to binary string"""
    # Handle both str and bytes input
    if isinstance(mac, bytes):
        mac = mac.decode('ascii')
    return b''.join(bytes([int(x, 16)]) for x in mac.split(':'))

def str2mac(s):
    """Convert binary string to MAC address format"""
    # Handle both str and bytes input (Python 2/3 compatibility)
    if isinstance(s, str):
        return ("%02x:" * len(s))[:-1] % tuple(map(ord, s))
    return ("%02x:" * len(s))[:-1] % tuple(s)

def warning(msg):
    """Print warning message"""
    warnings.warn(msg, stacklevel=2)

# Stub classes for random value generation (unused fuzzing code from Scapy)
# These are never called in dionaea but referenced in dead code paths
class RandNum:
    """Stub for random number generator"""
    def __init__(self, min=0, max=100):
        self.min = min
        self.max = max

class RandByte:
    """Stub for random byte generator"""
    pass

class RandShort:
    """Stub for random short generator"""
    pass

class RandInt:
    """Stub for random int generator"""
    pass

class RandLong:
    """Stub for random long generator"""
    pass

class RandSInt:
    """Stub for random signed int generator"""
    pass

class RandBin:
    """Stub for random binary data generator"""
    def __init__(self, size):
        self.size = size

class RandTermString:
    """Stub for random terminated string generator"""
    pass

class RandIP:
    """Stub for random IP generator"""
    pass

class RandMAC:
    """Stub for random MAC generator"""
    pass

# Placeholder for field length management deprecation warning
FIELD_LENGTH_MANAGEMENT_DEPRECATION = "Field length management is deprecated"
