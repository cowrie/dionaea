# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Any, Pattern
import logging
import re

logger = logging.getLogger("emu_scripts")


class BaseHandler:
    name: str = ""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config: dict[str, Any] = {}
        if isinstance(config, dict):
            self._config = config

        self.min_match_count: int = 0
        self._regex_detect: list[Pattern[bytes]] = []

        self._regex_url: Pattern[bytes] = re.compile(
            br"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
        )

    def run(self, data: bytes) -> list[bytes] | None:
        match_count = 0
        for regex in self._regex_detect:
            m = regex.search(data)
            if m:
                match_count += 1

        if match_count < self.min_match_count:
            logger.info("Match count for %s is %d should at least be %d", self.name, match_count, self.min_match_count)
            return None

        logger.info("Looking for URLs '%s'", self.name)
        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(m.group("url"))
        return urls


class RawURL:
    name: str = "raw_url"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config: dict[str, Any] = {}
        if isinstance(config, dict):
            self._config = config

        self._regex_url: Pattern[bytes] = re.compile(
            br"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
        )

    def run(self, data: bytes) -> list[bytes]:
        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(m.group("url"))
        return urls


class PowerShell(BaseHandler):
    name: str = "powershell"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        BaseHandler.__init__(self, config=config)

        self.min_match_count = 2
        self._regex_detect = [
            re.compile(br"New-Object\s+System\.Net\.WebClient"),
            re.compile(b"DownloadFile([^,]+?,[^,]+?)"),
            re.compile(b"Invoke-Expression([^)]+?)")
        ]

        self._regex_url = re.compile(
            b"\\w+\\s*=\\s*\"\\s*(?P<url>(http|ftp|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?)\\s*\""
        )


class VBScript(BaseHandler):
    name: str = "vbscript"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        BaseHandler.__init__(self, config=config)

        self.min_match_count = 1
        self._regex_detect = [
            re.compile(br"Set\s+\w+\s+=\s+CreateObject\(.*?(Msxml2.XMLHTTP|Wscript.Shell).*?\)")
        ]

        self._regex_url = re.compile(
            b"\\.Open\\s+\"GET\"\\s*,\\s*\"(?P<url>(http|ftp|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?)\""
        )
