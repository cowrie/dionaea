# ABOUTME: FTP control connection protocol handler with state machine dispatch.
# ABOUTME: Handles command parsing, login, and delegates to per-command handlers.

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import logging
import os
from pathlib import Path
import time

from dionaea.core import connection, incident

from .state import State, COMMAND_TABLE, RESPONSE

logger = logging.getLogger('ftp')


class FTPd(connection):
    protocol_name = "ftpd"
    shared_config_values = ("basedir", "response_msgs")

    def __init__(self, proto='tcp'):
        connection.__init__(self, proto)
        self.state = State.NOT_AUTHENTICATED
        self.user = ''
        self.cwd = '/'
        self.basedir = None
        self.dtp = None   # active data connection (PORT)
        self.dtf = None   # passive data listener (PASV)
        self.rename_from = None

        # Security state (RFC 4217)
        self.tls_active = False
        self.pbsz_done = False
        self.prot_level = 'C'

        # Copy default response messages; config can override
        self.response_msgs = dict(RESPONSE)

    def sendline(self, data):
        self.send(data + '\r\n')

    def reply(self, name, **kwargs):
        msg = self.response_msgs.get(name, '')
        self.sendline(msg.format(**kwargs))

    def handle_origin(self, parent):
        logger.debug("setting basedir to %s", parent.basedir)
        self.basedir = parent.basedir

    def handle_established(self):
        self.processors()
        self.reply("welcome_msg")

    def handle_io_in(self, data: bytes) -> int:
        logger.debug("%s", data.decode(errors='replace').rstrip('\r\n'))
        lastsep = data.rfind(b'\n')
        if lastsep == -1:
            logger.debug("data without linebreak")
            return 0

        lastsep += 1
        lines = data[:lastsep].splitlines(False)
        for line in lines:
            if not line:
                continue
            space = line.find(b' ')
            if space != -1:
                cmd = line[:space]
                arg = line[space + 1:]
            else:
                cmd = line
                arg = None
            self.processcmd(cmd, arg)
        return lastsep

    def processcmd(self, cmd_bytes, arg_bytes):
        cmd_str = cmd_bytes.decode('latin-1')
        arg_str = arg_bytes.decode('latin-1') if arg_bytes else ''

        i = incident("dionaea.modules.python.ftp.command")
        i.con = self
        i.command = cmd_bytes
        i.arguments = [arg_str] if arg_str else []
        i.report()

        cmd_upper = cmd_str.upper()

        # Look up in command table
        allowed_states = COMMAND_TABLE.get(cmd_upper)
        if allowed_states is None:
            self.reply("cmd_not_implmntd", command=cmd_upper)
            return

        # Check state validity
        if self.state not in allowed_states:
            if self.state == State.NOT_AUTHENTICATED:
                self.reply("not_logged_in")
            elif self.state == State.AWAITING_PASS:
                self.reply("bad_cmd_seq")
            elif self.state == State.RENAMING:
                self.reply("bad_cmd_seq")
            else:
                self.reply("not_logged_in")
            return

        # Dispatch to cmd_<NAME>
        handler = getattr(self, 'cmd_' + cmd_upper, None)
        if handler is None:
            self.reply("cmd_not_implmntd", command=cmd_upper)
            return
        handler(arg_str)

    # -- Login commands --

    def cmd_USER(self, arg):
        if not arg:
            self.reply("syntax_error_user_requires_arg")
            return
        self.state = State.AWAITING_PASS
        self.user = arg
        if arg == 'anonymous':
            self.reply("guest_name_ok_need_email")
        else:
            self.reply("usr_name_ok_need_pass", username=arg)

    def cmd_PASS(self, arg):
        if not arg:
            self.reply("syntax_error_pass_requires_arg")
            return

        i = incident("dionaea.modules.python.ftp.login")
        i.con = self
        i.username = self.user
        i.password = arg
        i.report()

        self.state = State.AUTHENTICATED
        if self.user == 'anonymous':
            self.reply("guest_logged_in_proceed")
        else:
            self.reply("usr_logged_in_proceed")

    # -- Pre-auth commands (valid in any state) --

    def cmd_FEAT(self, arg):
        self.send(
            '211-Features:\r\n'
            ' AUTH TLS\r\n'
            ' PBSZ\r\n'
            ' PROT\r\n'
            ' PASV\r\n'
            ' SIZE\r\n'
            ' MDTM\r\n'
            ' UTF8\r\n'
            '211 End\r\n'
        )

    def cmd_SYST(self, arg):
        self.reply("name_sys_type")

    def cmd_QUIT(self, arg):
        self.reply("goodbye_msg")
        self.close()

    def cmd_NOOP(self, arg):
        self.reply("cmd_ok")

    def cmd_HELP(self, arg):
        self.sendline('214 Help OK.')

    # -- File system commands --

    def real_path(self, p=None):
        """Resolve a virtual path to a real path, confined to basedir."""
        if p:
            name = str(Path(self.cwd) / p)
        else:
            name = self.cwd

        if name.startswith('/'):
            name = name[1:]
        name = str((Path(self.basedir) / name).resolve())
        return name

    def cmd_PWD(self, arg):
        self.reply("pwd_reply", cwd=self.cwd)

    def cmd_CWD(self, arg):
        cwd = self.real_path(arg)
        if not cwd.startswith(self.basedir):
            self.reply("file_not_found", filename=arg)
            return
        if Path(cwd).is_dir():
            self.cwd = cwd[len(self.basedir):] or '/'
            self.reply("req_file_actn_completed_ok")
        else:
            self.reply("file_not_found", filename=arg)

    def cmd_CDUP(self, arg):
        parent = str(Path(self.cwd).parent)
        self.cmd_CWD(parent)

    def cmd_TYPE(self, arg):
        if arg == 'I':
            self.reply("type_set_ok", mode='I')
        else:
            self.reply("cmd_not_implmntd_for_param", param=arg)

    def cmd_SIZE(self, arg):
        if not arg:
            self.reply("file_not_found", filename=arg)
            return
        filepath = self.real_path(arg)
        if not filepath.startswith(self.basedir):
            self.reply("file_not_found", filename=arg)
            return
        p = Path(filepath)
        if p.is_file():
            self.reply("file_status", value=str(p.stat().st_size))
        else:
            self.reply("file_not_found", filename=arg)

    def cmd_MDTM(self, arg):
        if not arg:
            self.reply("file_not_found", filename=arg)
            return
        filepath = self.real_path(arg)
        if not filepath.startswith(self.basedir):
            self.reply("file_not_found", filename=arg)
            return
        p = Path(filepath)
        if p.is_file():
            mtime = time.strftime('%Y%m%d%H%M%S', time.gmtime(p.stat().st_mtime))
            self.reply("file_status", value=mtime)
        else:
            self.reply("file_not_found", filename=arg)

    def cmd_DELE(self, arg):
        if not arg:
            self.reply("file_not_found", filename=arg)
            return
        filepath = self.real_path(arg)
        if not filepath.startswith(self.basedir):
            self.reply("permission_denied", path=arg)
            return
        p = Path(filepath)
        if p.is_file():
            p.unlink()
            self.reply("req_file_actn_completed_ok")
        else:
            self.reply("file_not_found", filename=arg)

    def cmd_RMD(self, arg):
        if not arg:
            self.reply("file_not_found", filename=arg)
            return
        dirpath = self.real_path(arg)
        if not dirpath.startswith(self.basedir):
            self.reply("file_not_found", filename=arg)
            return
        p = Path(dirpath)
        if p.is_dir():
            p.rmdir()
            self.reply("req_file_actn_completed_ok")
        else:
            self.reply("file_not_found", filename=arg)

    def cmd_MKD(self, arg):
        if not arg:
            self.reply("file_not_found", filename=arg)
            return
        dirpath = self.real_path(arg)
        if not dirpath.startswith(self.basedir):
            self.reply("file_not_found", filename=arg)
            return
        if Path(dirpath).is_dir():
            self.reply("permission_denied", path=arg)
            return
        Path(dirpath).mkdir()
        self.reply("req_file_actn_completed_ok")

    def cmd_RNFR(self, arg):
        if not arg:
            self.reply("file_not_found", filename=arg)
            return
        filepath = self.real_path(arg)
        if not filepath.startswith(self.basedir):
            self.reply("permission_denied", path=arg)
            return
        if not Path(filepath).exists():
            self.reply("file_not_found", filename=arg)
            return
        self.rename_from = filepath
        self.state = State.RENAMING
        self.reply("req_file_actn_pending_further_info")

    def cmd_RNTO(self, arg):
        if not arg:
            self.reply("file_not_found", filename=arg)
            return
        filepath = self.real_path(arg)
        if not filepath.startswith(self.basedir):
            self.reply("permission_denied", path=arg)
            return
        os.rename(self.rename_from, filepath)
        self.rename_from = None
        self.state = State.AUTHENTICATED
        self.reply("req_file_actn_completed_ok")

    def handle_error(self, err):
        pass

    def handle_disconnect(self):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        return 0
