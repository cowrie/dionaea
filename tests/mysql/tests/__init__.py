# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os

import pymysql


class SQLConnection:
    def __init__(self):
        self.cnx = None
        self.cursor = None
        self.connect()

    def __del__(self):
        self.disconnect()

    def connect(self):
        host = os.environ.get("DIONAEA_HOST", "127.0.0.1")
        port = int(os.environ.get("DIONAEA_MYSQL_PORT", "3306"))
        self.cnx = pymysql.connect(user="root", host=host, port=port)
        self.cursor = self.cnx.cursor()
        return self.cursor

    def disconnect(self):
        if self.cursor is not None:
            self.cursor.close()
        if self.cnx is not None:
            self.cnx.close()
