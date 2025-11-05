# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import connection

class echo(connection):
    def __init__(self, proto: str | None = None) -> None:
        print("echo init")
        connection.__init__(self, proto)
        self.timeouts.idle = 5.
        self.timeouts.sustain = 10.

    def handle_origin(self, parent: connection) -> None:
        print("origin!")
        print("parent {:s} {:s}:{:d}".format(
            parent.protocol, parent.local.host, parent.local.port))
        print("self {:s} {:s}:{:d} -> {:s}:{:d}".format(self.protocol,
                                                        self.local.host, self.local.port, self.remote.host, self.remote.port))

    def handle_established(self) -> None:
        print("new connection to serve!")
        self.send('welcome to reverse world!\n')

    def handle_timeout_idle(self) -> bool:
        self.send("you are idle!\n")
        return True

    def handle_timeout_sustain(self) -> bool:
        self.send("your sustain timeouted!\n")
        return False

    def handle_disconnect(self) -> bool:
        self.send("disconnecting you!\n")
        return True

    def handle_io_in(self, data: bytes) -> int:
        print('py_io_in\n')
        self.send(data[::-1][1:] + b'\n')
        return len(data)

#
#e = echo(proto='tcp')
#e.bind('0.0.0.0',4713,'')
#e.listen()
