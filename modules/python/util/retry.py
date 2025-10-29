#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Markus Koetter
# SPDX-FileCopyrightText: 2011-2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import socket
import os
import shutil
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--file",
        dest="filename"
    )
    parser.add_argument(
        "-H", "--host",
        dest="host"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        dest="port"
    )
    parser.add_argument(
        "-s", "--send",
        action="store_true",
        dest="send",
        default=False
    )
    parser.add_argument(
        "-r", "--recv",
        action="store_true",
        dest="recv",
        default=False
    )
    parser.add_argument(
        "-t", "--tempfile",
        dest="tempfile",
        default="retrystream"
    )
    parser.add_argument(
        "-u", "--udp",
        action="store_true",
        dest="udp",
        default=False
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        dest="verbose",
        default=False
    )
    options = parser.parse_args()

    if os.path.exists(options.tempfile):
        os.unlink(options.tempfile)
    shutil.copy(options.filename, options.tempfile + ".py")

    sys.path.append(".")
    stream_module = __import__(options.tempfile, fromlist=["stream"])
    stream = stream_module.stream

    print("doing " + options.filename)
    if options.send:
        if options.udp:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.connect((options.host, options.port))

    for i in stream:
        if i[0] == 'in':
            r = 0
            if options.send:
                r = s.send(i[1])
            if options.verbose:
                print('send %i of %i bytes' % (r, len(i[1])))
        if i[0] == 'out':
            x = ""
            if options.recv:
                x = s.recv(len(i[1]))
            if options.verbose:
                print('recv %i of %i bytes' % ( len(x), len(i[1])) )
            time.sleep(1)

    time.sleep(1)

if __name__ == '__main__':
    main()
