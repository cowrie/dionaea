# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010 Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader, Timer
from dionaea.core import ihandler, incident

import logging
import json
import os
import sqlite3

logger = logging.getLogger("virustotal")
logger.setLevel(logging.DEBUG)

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalHandlerLoader(IHandlerLoader):
    name = "virustotal"

    @classmethod
    def start(cls, config=None):
        return virustotalhandler("*", config=config)


class virustotalhandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug(f"{self.__class__.__name__} ready!")
        ihandler.__init__(self, path)
        self.apikey = config.get("apikey", "")
        if not self.apikey or not self.apikey.strip("."):
            logger.warning("VirusTotal API key not configured")
        else:
            self._verify_api_key()
        comment = config.get("comment")
        if comment is None:
            comment = "This sample was captured in the wild and uploaded by the dionaea honeypot.\n#honeypot #malware #networkworm"
        self.comment = comment

        p = config.get("file")
        self.dbh = sqlite3.connect(p, check_same_thread=False)
        self.cursor = self.dbh.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS backlogfiles (
                backlogfile INTEGER PRIMARY KEY,
                status TEXT NOT NULL, -- new, submit, query, comment
                sha256_hash TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                scan_id TEXT,
                lastcheck_time INTEGER,
                submit_time INTEGER
            );""")

        self.backlog_timer = Timer(
            interval=20,
            delay=0,
            function=self.__handle_backlog_timeout,
            repeat=True,
        )
        self.backlog_timer.start()

    def _vt_request(self, method, endpoint, json_body=None):
        """Make an API v3 request. Returns (status_code, parsed_json) or (None, None) on error."""
        from urllib.request import Request, urlopen
        from urllib.error import URLError, HTTPError

        url = f"{VT_API_BASE}{endpoint}"
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode()

        req = Request(url, data=data, method=method)
        req.add_header("x-apikey", self.apikey)
        if json_body is not None:
            req.add_header("Content-Type", "application/json")

        try:
            resp = urlopen(req, timeout=30)
            body = resp.read()
            return resp.status, json.loads(body) if body else {}
        except HTTPError as e:
            body = e.read()
            try:
                j = json.loads(body) if body else {}
            except (json.JSONDecodeError, ValueError):
                j = {}
            return e.code, j
        except (URLError, OSError) as e:
            logger.warning("VirusTotal API request failed: %s %s: %s", method, endpoint, e)
            return None, None

    def _vt_upload_file(self, file_path):
        """Upload a file via multipart POST to /files. Returns (status_code, parsed_json)."""
        from urllib.request import Request, urlopen
        from urllib.error import URLError, HTTPError

        boundary = "----DionaeaUploadBoundary"
        filename = os.path.basename(file_path)

        with open(file_path, "rb") as f:
            file_data = f.read()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
        ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

        url = f"{VT_API_BASE}/files"
        req = Request(url, data=body, method="POST")
        req.add_header("x-apikey", self.apikey)
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

        try:
            resp = urlopen(req, timeout=120)
            return resp.status, json.loads(resp.read())
        except HTTPError as e:
            body = e.read()
            try:
                j = json.loads(body) if body else {}
            except (json.JSONDecodeError, ValueError):
                j = {}
            return e.code, j
        except (URLError, OSError) as e:
            logger.warning("VirusTotal file upload failed: %s", e)
            return None, None

    def _verify_api_key(self):
        """Check the API key against VT v3 by requesting a report for a dummy hash."""
        dummy_hash = "0" * 64
        status, _ = self._vt_request("GET", f"/files/{dummy_hash}")
        if status is None:
            logger.warning("VirusTotal API unreachable during key verification")
        elif status in (401, 403):
            logger.warning("VirusTotal API key is invalid (HTTP %d)", status)
        elif status in (200, 404):
            # 200 = hash found, 404 = hash not found; either means key is valid
            logger.info("VirusTotal API key is valid")
        else:
            logger.warning("VirusTotal API key check returned unexpected HTTP %d", status)

    def __handle_backlog_timeout(self):
        # try to comment on files
        # comment on files which were submitted at least 60 seconds ago
        sfs = self.cursor.execute(
            """SELECT backlogfile, sha256_hash, path FROM backlogfiles WHERE status = 'comment' AND submit_time < strftime("%s",'now')-1*60 LIMIT 1"""
        )
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'comment-' WHERE backlogfile = ?""",
                (sf[0],),
            )
            self.dbh.commit()
            self._make_comment(sf[0], sf[1], "comment")
            return

        # try to receive reports for files we submitted
        sfs = self.cursor.execute(
            """SELECT backlogfile, sha256_hash, path FROM backlogfiles WHERE status = 'query' AND submit_time < strftime("%s",'now')-15*60 AND lastcheck_time < strftime("%s",'now')-15*60 LIMIT 1"""
        )
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'query-' WHERE backlogfile = ?""",
                (sf[0],),
            )
            self.dbh.commit()
            self._get_file_report(sf[0], sf[1], "query")
            return

        # submit files not known to virustotal
        sfs = self.cursor.execute(
            """SELECT backlogfile, sha256_hash, path FROM backlogfiles WHERE status = 'submit' LIMIT 1"""
        )
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'submit-' WHERE backlogfile = ?""",
                (sf[0],),
            )
            self.dbh.commit()
            self._scan_file(sf[0], sf[1], sf[2], "submit")
            return

        # query new files
        sfs = self.cursor.execute(
            """SELECT backlogfile, sha256_hash, path FROM backlogfiles WHERE status = 'new' ORDER BY timestamp DESC LIMIT 1"""
        )
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'new-' WHERE backlogfile = ?""",
                (sf[0],),
            )
            self.dbh.commit()
            self._get_file_report(sf[0], sf[1], "new")
            return

    def stop(self):
        self.backlog_timer.cancel()
        self.backlog_timer = None
        self.cursor.close()
        self.dbh.close()

    def handle_incident(self, icd):
        pass

    def handle_incident_dionaea_download_complete_unique(self, icd):
        self.cursor.execute(
            """INSERT INTO backlogfiles (sha256_hash, path, status, timestamp) VALUES (?,?,?,strftime("%s",'now')) """,
            (icd.sha256hash, icd.file, "new"),
        )

    def _get_file_report(self, backlogfile, sha256_hash, status):
        status_code, j = self._vt_request("GET", f"/files/{sha256_hash}")

        if status_code is None:
            # Network error — reset status for retry
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""",
                (status, backlogfile),
            )
            self.dbh.commit()
            return

        if status_code == 429:
            logger.warning("VirusTotal API throttle for %s", sha256_hash[:16])
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""",
                (status, backlogfile),
            )
            self.dbh.commit()
        elif status_code in (401, 403):
            logger.warning("VirusTotal API key invalid or missing")
        elif status_code == 404:
            logger.info(
                "VirusTotal: file %s not found, queuing for submission",
                sha256_hash[:16],
            )
            if status == "new":
                self.cursor.execute(
                    """UPDATE backlogfiles SET status = 'submit', lastcheck_time = strftime("%s",'now') WHERE backlogfile = ?""",
                    (backlogfile,),
                )
            elif status == "query":
                self.cursor.execute(
                    """UPDATE backlogfiles SET lastcheck_time = strftime("%s",'now') WHERE backlogfile = ?""",
                    (backlogfile,),
                )
            self.dbh.commit()
        elif status_code == 200:
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            logger.info(
                "VirusTotal: file %s known, detection %d/%d",
                sha256_hash[:16],
                positives,
                total,
            )
            self.cursor.execute(
                """DELETE FROM backlogfiles WHERE backlogfile = ?""", (backlogfile,)
            )
            self.dbh.commit()

            logger.debug("report %s", j)

            attrs = j.get("data", {}).get("attributes", {})
            permalink = f"https://www.virustotal.com/gui/file/{sha256_hash}"
            analysis_date = attrs.get("last_analysis_date", 0)
            results = attrs.get("last_analysis_results", {})

            i = incident("dionaea.modules.python.virustotal.report")
            i.sha256hash = sha256_hash
            i.permalink = permalink
            i.analysis_date = analysis_date
            i.positives = positives
            i.total = total
            # Pack scan results: {engine: result_string_or_empty}
            scans = {}
            for engine, detail in results.items():
                scans[engine] = detail.get("result") or ""
            i.scans = scans
            i.report()
        else:
            logger.warning("VirusTotal unexpected HTTP %d for %s", status_code, sha256_hash[:16])

    def _scan_file(self, backlogfile, sha256_hash, path, status):
        logger.info("VirusTotal: submitting file %s", sha256_hash)

        status_code, j = self._vt_upload_file(path)

        if status_code is None:
            # Network error — reset status for retry
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""",
                (status, backlogfile),
            )
            self.dbh.commit()
            return

        if status_code == 429:
            logger.warning(
                "VirusTotal API throttle during file submission for %s",
                sha256_hash[:16],
            )
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""",
                (status, backlogfile),
            )
            self.dbh.commit()
        elif status_code in (401, 403):
            logger.warning("VirusTotal API key invalid or missing")
        elif status_code == 200:
            analysis_id = j.get("data", {}).get("id", "")
            logger.info(
                "VirusTotal: file %s submitted successfully",
                sha256_hash[:16],
            )
            self.cursor.execute(
                """UPDATE backlogfiles SET scan_id = ?, status = 'comment', submit_time = strftime("%s",'now') WHERE backlogfile = ?""",
                (analysis_id, backlogfile),
            )
            self.dbh.commit()
        else:
            logger.warning(
                "VirusTotal unexpected HTTP %d during file submission: %s", status_code, j
            )

    def _make_comment(self, backlogfile, sha256_hash, status):
        status_code, j = self._vt_request("POST", f"/files/{sha256_hash}/comments", {
            "data": {
                "type": "comment",
                "attributes": {
                    "text": self.comment,
                },
            },
        })

        if status_code is None:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""",
                (status, backlogfile),
            )
            self.dbh.commit()
            return

        if status_code == 429:
            logger.warning(
                "VirusTotal API throttle during comment for %s", sha256_hash[:16]
            )
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""",
                (status, backlogfile),
            )
            self.dbh.commit()
        elif status_code in (401, 403):
            logger.warning("VirusTotal API key invalid or missing")
        elif status_code in (200, 201):
            logger.info("VirusTotal: comment posted for %s", sha256_hash[:16])
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'query' WHERE backlogfile = ? """,
                (backlogfile,),
            )
            self.dbh.commit()
        else:
            logger.warning("VirusTotal unexpected HTTP %d during comment: %s", status_code, j)
