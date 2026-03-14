# ABOUTME: FTP protocol state machine definitions.
# ABOUTME: State enum, command validity table, and response code templates.

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import enum


class State(enum.Enum):
    NOT_AUTHENTICATED = "not_authenticated"
    AWAITING_PASS = "awaiting_pass"
    AUTHENTICATED = "authenticated"
    RENAMING = "renaming"


ANY = frozenset(State)

COMMAND_TABLE = {
    # Always valid
    'QUIT': ANY,
    'FEAT': ANY,
    'NOOP': ANY,
    'SYST': ANY,
    'HELP': ANY,

    # Security (RFC 4217 / RFC 2228)
    'AUTH': {State.NOT_AUTHENTICATED, State.AUTHENTICATED},
    'PBSZ': {State.NOT_AUTHENTICATED, State.AUTHENTICATED},
    'PROT': {State.NOT_AUTHENTICATED, State.AUTHENTICATED},
    'CCC':  {State.AUTHENTICATED},

    # Login sequence
    'USER': {State.NOT_AUTHENTICATED, State.AUTHENTICATED},
    'PASS': {State.AWAITING_PASS},

    # Transfer setup
    'PORT': {State.AUTHENTICATED},
    'PASV': {State.AUTHENTICATED},
    'TYPE': {State.AUTHENTICATED},

    # File operations
    'RETR': {State.AUTHENTICATED},
    'STOR': {State.AUTHENTICATED},
    'LIST': {State.AUTHENTICATED},
    'PWD':  {State.AUTHENTICATED},
    'CWD':  {State.AUTHENTICATED},
    'CDUP': {State.AUTHENTICATED},
    'SIZE': {State.AUTHENTICATED},
    'MDTM': {State.AUTHENTICATED},
    'DELE': {State.AUTHENTICATED},
    'RMD':  {State.AUTHENTICATED},
    'MKD':  {State.AUTHENTICATED},
    'RNFR': {State.AUTHENTICATED},
    'RNTO': {State.RENAMING},
}


RESPONSE = {
    # 100s
    "data_cnx_already_open_start_xfr": "125 Data connection already open, starting transfer",
    "file_status_ok_open_data_cnx":    "150 File status okay; about to open data connection.",

    # 200s
    "cmd_ok":                          "200 Command OK",
    "type_set_ok":                     "200 Type set to {mode}.",
    "entering_port_mode":              "200 PORT OK",
    "sys_status_or_help_reply":        "211 System status reply",
    "dir_status":                      "212 {value}",
    "file_status":                     "213 {value}",
    "name_sys_type":                   "215 UNIX Type: L8",
    "welcome_msg":                     "220 Welcome to the ftp service",
    "svc_ready_for_new_user":          "220 Service ready",
    "goodbye_msg":                     "221 Goodbye.",
    "data_cnx_open_no_xfr_in_progress": "225 data connection open, no transfer in progress",
    "closing_data_cnx":                "226 Abort successful",
    "txfr_complete_ok":                "226 Transfer Complete.",
    "entering_pasv_mode":              "227 Entering Passive Mode ({host}).",
    "usr_logged_in_proceed":           "230 User logged in, proceed",
    "guest_logged_in_proceed":         "230 Anonymous login ok, access restrictions apply.",
    "req_file_actn_completed_ok":      "250 Requested File Action Completed OK",
    "pwd_reply":                       '257 "{cwd}"',

    # 300s
    "usr_name_ok_need_pass":           "331 Password required for {username}.",
    "guest_name_ok_need_email":        "331 Guest login ok, type your email address as password.",
    "req_file_actn_pending_further_info": "350 Requested file action pending further information.",

    # 400s
    "cant_open_data_cnx":              "425 Can't open data connection.",
    "cnx_closed_txfr_aborted":         "426 Transfer aborted.  Data connection closed.",

    # 500s
    "syntax_error_pass_requires_arg":  "500 Syntax error: PASS requires an argument",
    "syntax_error_user_requires_arg":  "500 Syntax error: USER requires an argument",
    "syntax_err_in_args":              "501 syntax error in argument(s) {command}.",
    "cmd_not_implmntd":                "502 Command '{command}' not implemented",
    "bad_cmd_seq":                     "503 Bad sequence of commands",
    "bad_cmd_seq_pass_after_user":     "503 Incorrect sequence of commands: PASS required after USER",
    "cmd_not_implmntd_for_param":      "504 Not implemented for parameter '{param}'.",
    "not_logged_in":                   "530 Please login with USER and PASS.",
    "auth_failure":                    "530 Sorry, Authentication failed.",
    "file_not_found":                  "550 {filename}: No such file or directory.",
    "permission_denied":               "550 {path}: Permission denied.",

    # RFC 4217 (STARTTLS)
    "auth_tls_ok":                     "234 AUTH TLS successful",
    "pbsz_ok":                         "200 PBSZ=0",
    "prot_ok":                         "200 Protection level set to {level}",
    "prot_unknown":                    "504 Protection level '{level}' not understood",
    "security_required":               "503 Security exchange not yet completed",
    "pbsz_required":                   "503 PBSZ required before PROT",
    "ccc_refused":                     "534 CCC not supported",
    "auth_already_active":             "503 AUTH already completed",
    "pbsz_bad_value":                  "501 PBSZ must be 0 for TLS",
}
