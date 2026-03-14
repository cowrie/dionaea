# ABOUTME: FTP data channel connection classes for passive and active transfers.
# ABOUTME: Handles LIST directory listings, RETR file sends, and STOR file receives.

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import logging
import stat
import time
from pathlib import Path

from dionaea.core import connection

logger = logging.getLogger('ftp')


class FTPDataCon(connection):
    """Base class for FTP data connections (both passive and active)."""

    def __init__(self, proto='tcp', ctrl=None):
        connection.__init__(self, proto)
        self.ctrl = ctrl
        self.mode = None
        self.file = None
        self.data = []
        self.off = 0

    def handle_error(self, err):
        if self.ctrl:
            self.ctrl.reply("cant_open_data_cnx")

    def send_list(self, path, strip_len):
        """Format and send a directory listing."""
        self.mode = 'list'
        p = Path(path)
        if p.is_dir():
            self.data = [self._format_entry(str(p / f.name), strip_len)
                         for f in p.iterdir()]
        elif p.is_file():
            self.data = [self._format_entry(path, strip_len)]
        else:
            self.data = []

        if self.data:
            self.off = 1
            self.send(self.data[0] + '\r\n')
        else:
            self._finish_transfer()

    def _format_entry(self, filepath, strip_len):
        """Format a single directory listing entry in ls -l style."""
        name = filepath[strip_len:]
        s = Path(filepath).stat()
        is_dir = stat.S_ISDIR(s.st_mode)
        perms = stat.S_IMODE(s.st_mode)

        def fmt_mode(mode):
            return ''.join(
                'rwx'[n % 3] if mode & (256 >> n) else '-'
                for n in range(9)
            )

        def fmt_date(mtime):
            now = time.gmtime()
            mt = time.gmtime(mtime)
            if now.tm_year != mt.tm_year:
                return f'{mt.tm_mon} {mt.tm_mday:02d} {mt.tm_year:5d}'
            return f'{mt.tm_mon} {mt.tm_mday:02d} {mt.tm_hour:02d}:{mt.tm_min:02d}'

        d = 'd' if is_dir else '-'
        return (
            f'{d}{fmt_mode(perms)}{s.st_nlink:4d} '
            f'{s.st_uid:<9} {s.st_gid:<9} {s.st_size:15d} '
            f'{fmt_date(s.st_mtime):>12} {name}'
        )

    def send_file(self, filepath):
        """Start sending a file."""
        self.mode = 'file'
        self.file = open(filepath, 'rb')
        self.handle_io_out()

    def recv_file(self, filepath):
        """Start receiving a file."""
        self.mode = 'recv_file'
        self.file = open(filepath, 'wb+')

    def handle_io_in(self, data: bytes) -> int:
        if self.mode == 'recv_file' and self.file:
            self.file.write(data)
        return len(data)

    def handle_io_out(self):
        if self.mode == 'list':
            if self.off < len(self.data):
                self.send(self.data[self.off] + '\r\n')
                self.off += 1
            else:
                self._finish_transfer()

        elif self.mode == 'file':
            chunk = self.file.read(1024)
            self.send(chunk)
            if len(chunk) < 1024 and self.mode is not None:
                self.mode = None
                self.file.close()
                self.file = None
                self._finish_transfer()

    def _finish_transfer(self):
        self.close()
        if self.ctrl:
            self.ctrl.dtp = None
            self.ctrl.reply("txfr_complete_ok")

    def handle_disconnect(self):
        if self.ctrl:
            if self.ctrl.dtf:
                self.ctrl.dtf = None
            if self.ctrl.dtp:
                self.ctrl.dtp = None
            if self.mode in ('file', 'recv_file') and self.file:
                self.file.close()
                if self.mode == 'recv_file':
                    self.ctrl.reply("txfr_complete_ok")
        return 0

    def handle_origin(self, parent):
        pass


class FTPDataListen(FTPDataCon):
    """Passive mode data connection listener."""
    protocol_name = "ftpdatalisten"

    def __init__(self, host=None, port=None, ctrl=None, proto='tcp'):
        FTPDataCon.__init__(self, proto=proto, ctrl=ctrl)
        if host is not None:
            self.bind(host, port)
            self.listen(1)

    def handle_established(self):
        logger.debug("DATA connection established")

    def handle_origin(self, parent):
        FTPDataCon.handle_origin(self, parent)
        self.ctrl = parent.ctrl
        self.ctrl.dtp = self
        self.ctrl.dtf = None
        parent.ctrl = None
        parent.close()


class FTPDataConnect(FTPDataCon):
    """Active mode data connection."""
    protocol_name = "ftpdataconnect"

    def __init__(self, host=None, port=None, ctrl=None, prot_p=False):
        FTPDataCon.__init__(self, proto='tcp', ctrl=ctrl)
        self.prot_p = prot_p
        if host is not None:
            self.connect(host, port)

    def handle_established(self):
        logger.debug("DATA connection established")
        if self.prot_p:
            self.start_tls()
        self.ctrl.reply("entering_port_mode")
