# ABOUTME: NetBIOS Name Service (NBNS) honeypot module for dionaea
# ABOUTME: Captures name queries (especially WPAD) for Hot Potato style attack detection
#
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 dionaea developers
#
# SPDX-License-Identifier: GPL-2.0-or-later

from .nbns import NBNSService, NBNSDatagramService

__all__ = ['NBNSService', 'NBNSDatagramService']
