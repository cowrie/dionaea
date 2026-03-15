# ABOUTME: Unit tests for the FTP state machine module.
# ABOUTME: Verifies State enum, COMMAND_TABLE completeness, and RESPONSE dict.

# SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial


from dionaea.ftp.state import State, COMMAND_TABLE, RESPONSE, ANY


class TestStateEnum:
    def test_all_states_exist(self):
        assert State.NOT_AUTHENTICATED.value == "not_authenticated"
        assert State.AWAITING_PASS.value == "awaiting_pass"
        assert State.AUTHENTICATED.value == "authenticated"
        assert State.RENAMING.value == "renaming"

    def test_exactly_four_states(self):
        assert len(State) == 4


class TestCommandTable:
    def test_any_is_all_states(self):
        assert ANY == frozenset(State)

    def test_always_valid_commands(self):
        for cmd in ("QUIT", "FEAT", "NOOP", "SYST", "HELP"):
            assert COMMAND_TABLE[cmd] == ANY, f"{cmd} should be valid in any state"

    def test_login_commands(self):
        assert State.NOT_AUTHENTICATED in COMMAND_TABLE["USER"]
        assert State.AWAITING_PASS not in COMMAND_TABLE["USER"]
        assert COMMAND_TABLE["PASS"] == {State.AWAITING_PASS}

    def test_auth_required_commands(self):
        auth_only = [
            "PORT",
            "PASV",
            "TYPE",
            "RETR",
            "STOR",
            "LIST",
            "PWD",
            "CWD",
            "CDUP",
            "SIZE",
            "MDTM",
            "DELE",
            "RMD",
            "MKD",
            "RNFR",
        ]
        for cmd in auth_only:
            assert COMMAND_TABLE[cmd] == {State.AUTHENTICATED}, (
                f"{cmd} should require AUTHENTICATED state"
            )

    def test_rnto_requires_renaming(self):
        assert COMMAND_TABLE["RNTO"] == {State.RENAMING}

    def test_security_commands(self):
        for cmd in ("AUTH", "PBSZ", "PROT"):
            allowed = COMMAND_TABLE[cmd]
            assert State.NOT_AUTHENTICATED in allowed
            assert State.AUTHENTICATED in allowed

        assert COMMAND_TABLE["CCC"] == {State.AUTHENTICATED}

    def test_all_commands_map_to_valid_states(self):
        for cmd, states in COMMAND_TABLE.items():
            assert isinstance(states, (set, frozenset)), (
                f"{cmd} should map to a set of states"
            )
            for s in states:
                assert isinstance(s, State), f"{cmd} contains non-State value: {s}"


class TestResponseDict:
    def test_core_responses_exist(self):
        required = [
            "welcome_msg",
            "goodbye_msg",
            "usr_logged_in_proceed",
            "guest_logged_in_proceed",
            "usr_name_ok_need_pass",
            "guest_name_ok_need_email",
            "not_logged_in",
            "cmd_not_implmntd",
            "pwd_reply",
            "cmd_ok",
        ]
        for key in required:
            assert key in RESPONSE, f"Missing response: {key}"

    def test_rfc4217_responses_exist(self):
        rfc4217 = [
            "auth_tls_ok",
            "pbsz_ok",
            "prot_ok",
            "prot_unknown",
            "security_required",
            "pbsz_required",
            "bad_cmd_seq",
            "ccc_refused",
            "auth_already_active",
            "pbsz_bad_value",
        ]
        for key in rfc4217:
            assert key in RESPONSE, f"Missing RFC 4217 response: {key}"

    def test_responses_start_with_code(self):
        for key, msg in RESPONSE.items():
            # Multi-line responses (like FEAT) start with code + dash
            first_char = msg[0]
            assert first_char.isdigit(), (
                f"Response '{key}' should start with a digit: {msg}"
            )
