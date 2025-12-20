# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010 Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader, Timer
from dionaea.core import ihandler, incident

import logging
import json
import uuid
import sqlite3

logger = logging.getLogger('virustotal')
logger.setLevel(logging.DEBUG)


class VirusTotalHandlerLoader(IHandlerLoader):
    name = "virustotal"

    @classmethod
    def start(cls, config=None):
        return virustotalhandler("*", config=config)


class vtreport:
    def __init__(self, backlogfile, md5hash, sha256hash, file, status):
        self.backlogfile = backlogfile
        self.md5hash = md5hash
        self.sha256hash = sha256hash
        self.file = file
        self.status = status

class virustotalhandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)
        self.apikey = config.get("apikey")
        comment = config.get("comment")
        if comment is None:
            comment = "This sample was captured in the wild and uploaded by the dionaea honeypot.\n#honeypot #malware #networkworm"
        self.comment = comment
        self.cookies = {}

        p = config.get("file")
        self.dbh = sqlite3.connect(p, check_same_thread=False)
        self.cursor = self.dbh.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS backlogfiles (
                backlogfile INTEGER PRIMARY KEY,
                status TEXT NOT NULL, -- new, submit, query, comment
                md5_hash TEXT NOT NULL,
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

    def __handle_backlog_timeout(self):
        logger.debug("backlog_timeout")

        # try to comment on files
        # comment on files which were submitted at least 60 seconds ago
        sfs = self.cursor.execute(
            """SELECT backlogfile, md5_hash, sha256_hash, path FROM backlogfiles WHERE status = 'comment' AND submit_time < strftime("%s",'now')-1*60 LIMIT 1""")
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'comment-' WHERE backlogfile = ?""", (sf[0],))
            self.dbh.commit()
            self.make_comment(sf[0], sf[1], sf[2], sf[3], 'comment')
            return

        # try to receive reports for files we submitted
        sfs = self.cursor.execute(
            """SELECT backlogfile, md5_hash, sha256_hash, path FROM backlogfiles WHERE status = 'query' AND submit_time < strftime("%s",'now')-15*60 AND lastcheck_time < strftime("%s",'now')-15*60 LIMIT 1""")
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'query-' WHERE backlogfile = ?""", (sf[0],))
            self.dbh.commit()
            self.get_file_report(sf[0], sf[1], sf[2], sf[3], 'query')
            return

        # submit files not known to virustotal
        sfs = self.cursor.execute(
            """SELECT backlogfile, md5_hash, sha256_hash, path FROM backlogfiles WHERE status = 'submit' LIMIT 1""")
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'submit-' WHERE backlogfile = ?""", (sf[0],))
            self.dbh.commit()
            self.scan_file(sf[0], sf[1], sf[2], sf[3], 'submit')
            return

        # query new files
        sfs = self.cursor.execute(
            """SELECT backlogfile, md5_hash, sha256_hash, path FROM backlogfiles WHERE status = 'new' ORDER BY timestamp DESC LIMIT 1""")
        for sf in sfs:
            self.cursor.execute(
                """UPDATE backlogfiles SET status = 'new-' WHERE backlogfile = ?""", (sf[0],))
            self.dbh.commit()
            self.get_file_report(sf[0], sf[1], sf[2], sf[3], 'new')
            return

    def stop(self):
        self.backlog_timer.cancel()
        self.backlog_timer = None

    def handle_incident(self, icd):
        pass

    def handle_incident_dionaea_download_complete_unique(self, icd):
        self.cursor.execute(
            """INSERT INTO backlogfiles (md5_hash, sha256_hash, path, status, timestamp) VALUES (?,?,?,?,strftime("%s",'now')) """, (icd.md5hash, icd.sha256hash, icd.file, 'new'))

    def get_file_report(self, backlogfile, md5_hash, sha256_hash, path, status):
        cookie = str(uuid.uuid4())
        self.cookies[cookie] = vtreport(backlogfile, md5_hash, sha256_hash, path, status)

        i = incident("dionaea.upload.request")
        i._url = "https://www.virustotal.com/vtapi/v2/file/report"
        i.resource = sha256_hash
        i.apikey = self.apikey
        i._callback = "dionaea.modules.python.virustotal.get_file_report"
        i._userdata = cookie
        i.report()

    def handle_incident_dionaea_modules_python_virustotal_get_file_report(self, icd):
        with open(icd.path) as f:
            j = json.load(f)

        cookie = icd._userdata
        vtr = self.cookies[cookie]
        response_code = j.get('response_code')
        logger.debug("VirusTotal response_code=%s for %s", response_code, vtr.sha256hash[:16])

        if response_code == -2:
            logger.warning("VirusTotal API throttle for %s", vtr.sha256hash[:16])
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""", (vtr.status, vtr.backlogfile))
            self.dbh.commit()
        elif response_code == -1:
            logger.warning("VirusTotal API key invalid or missing")
        elif response_code == 0:  # file unknown
            logger.info("VirusTotal: file %s not found, queuing for submission", vtr.sha256hash[:16])
            # mark for submit
            if vtr.status == 'new':
                self.cursor.execute(
                    """UPDATE backlogfiles SET status = 'submit', lastcheck_time = strftime("%s",'now') WHERE backlogfile = ?""", (vtr.backlogfile,))
            elif vtr.status == 'query':
                self.cursor.execute(
                    """UPDATE backlogfiles SET lastcheck_time = strftime("%s",'now') WHERE backlogfile = ?""", (vtr.backlogfile,))
            self.dbh.commit()
        elif response_code == 1:  # file known
            positives = j.get('positives', 0)
            total = j.get('total', 0)
            logger.info("VirusTotal: file %s known, detection %d/%d", vtr.sha256hash[:16], positives, total)
            self.cursor.execute(
                """DELETE FROM backlogfiles WHERE backlogfile = ?""", (vtr.backlogfile,) )
            self.dbh.commit()

            logger.debug(f"report {j}" )

            i = incident("dionaea.modules.python.virustotal.report")
            i.md5hash = vtr.md5hash
            i.path = icd.path
            i.report()
        else:
            logger.warning("VirusTotal unexpected response: %s", j)
        del self.cookies[cookie]

    def scan_file(self, backlogfile, md5_hash, sha256_hash, path, status):
        logger.warning("VirusTotal: submitting file %s (md5: %s)", sha256_hash, md5_hash)
        cookie = str(uuid.uuid4())
        self.cookies[cookie] = vtreport(backlogfile, md5_hash, sha256_hash, path, status)

        i = incident("dionaea.upload.request")
        i._url = "https://www.virustotal.com/vtapi/v2/file/scan"
        i.apikey = self.apikey
        i.set('file://file', path)
        i._callback = "dionaea.modules.python.virustotal_scan_file"
        i._userdata = cookie
        i.report()


    def handle_incident_dionaea_modules_python_virustotal_scan_file(self, icd):
        with open(icd.path) as f:
            j = json.load(f)

        cookie = icd._userdata
        vtr = self.cookies[cookie]
        response_code = j.get('response_code')
        logger.debug("VirusTotal scan_file response_code=%s for %s", response_code, vtr.sha256hash[:16])

        if response_code == -2:
            logger.warning("VirusTotal API throttle during file submission for %s", vtr.sha256hash[:16])
            self.cursor.execute(
                """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""", (vtr.status, vtr.backlogfile))
            self.dbh.commit()
        elif response_code == -1:
            logger.warning("VirusTotal API key invalid or missing")
        elif response_code == 1:
            scan_id = j['scan_id']
            logger.info("VirusTotal: file %s submitted successfully, scan_id: %s", vtr.sha256hash[:16], scan_id[:16])
            # recycle this entry for the query
            self.cursor.execute(
                """UPDATE backlogfiles SET scan_id = ?, status = 'comment', submit_time = strftime("%s",'now') WHERE backlogfile = ?""", (scan_id, vtr.backlogfile,))
            self.dbh.commit()
        else:
            logger.warning("VirusTotal unexpected response during file submission: %s", j)
        del self.cookies[cookie]

    def make_comment(self, backlogfile, md5_hash, sha256_hash, path, status):
        cookie = str(uuid.uuid4())
        self.cookies[cookie] = vtreport(backlogfile, md5_hash, sha256_hash, path, status)

        i = incident("dionaea.upload.request")
        i._url = "https://www.virustotal.com/vtapi/v2/comments/put"
        i.apikey = self.apikey
        i.comment = self.comment
        i.resource = sha256_hash
        i._callback = "dionaea.modules.python.virustotal_make_comment"
        i._userdata = cookie
        i.report()

    def handle_incident_dionaea_modules_python_virustotal_make_comment(self, icd):
        cookie = icd._userdata
        vtr = self.cookies[cookie]
        try:
            with open(icd.path) as f:
                j = json.load(f)
            response_code = j.get('response_code')
            logger.debug("VirusTotal make_comment response_code=%s for %s", response_code, vtr.sha256hash[:16])

            if response_code == -2:
                logger.warning("VirusTotal API throttle during comment for %s", vtr.sha256hash[:16])
                self.cursor.execute(
                    """UPDATE backlogfiles SET status = ? WHERE backlogfile = ?""", (vtr.status, vtr.backlogfile))
                self.dbh.commit()
            elif response_code == -1:
                logger.warning("VirusTotal API key invalid or missing")
            elif response_code == 1:
                logger.info("VirusTotal: comment posted for %s", vtr.sha256hash[:16])
                self.cursor.execute(
                    """UPDATE backlogfiles SET status = 'query' WHERE backlogfile = ? """, (vtr.backlogfile, ))
                self.dbh.commit()
            else:
                logger.warning("VirusTotal unexpected response during comment: %s", j)
        except Exception as e:
            logger.warning("VirusTotal comment response parse error: %s", e)
        del self.cookies[cookie]
