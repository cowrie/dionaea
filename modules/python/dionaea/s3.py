# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 Tan Kean Siong
#
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Any
from dionaea.core import ihandler, incident
from dionaea import IHandlerLoader

import logging

logger = logging.getLogger('s3')
logger.setLevel(logging.DEBUG)

try:
    import boto3  # type: ignore[import-not-found]
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    logger.debug("boto3 not available, S3 handler will be disabled")


class S3HandlerLoader(IHandlerLoader):
    name = "s3"

    @classmethod
    def start(cls, config: dict[str, Any] | None = None) -> 's3handler | None':
        if not BOTO3_AVAILABLE:
            logger.warning("S3 handler not started: boto3 library not installed")
            return None
        return s3handler("*", config=config)


class s3handler(ihandler):
    def __init__(self, path: str, config: dict[str, Any] | None = None) -> None:
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

        if config is None:
            config = {}
        self.bucket_name: str | None = config.get("bucket_name")
        self.region_name: str | None = config.get("region_name")
        self.access_key_id: str | None = config.get("access_key_id")
        self.secret_access_key: str | None = config.get("secret_access_key")
        self.endpoint_url: str | None = config.get("endpoint_url")
        self.verify: bool | str | None = config.get("verify")
        self.s3_dest_folder: str | None = config.get("s3_dest_folder")
        self.s3: Any = None


    def handle_incident(self, icd: incident) -> None:
        pass

    def handle_incident_dionaea_download_complete_unique(self, icd: incident) -> None:

        # Dionaea will upload unique samples to Amazon S3 bucket with Boto3 (AWS SDK Python)
        # Create an S3 client
        try:
            self.s3 = boto3.client(
                    's3',
                    self.region_name,
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                    endpoint_url=self.endpoint_url or None,
                    verify=self.verify)

            # Uploads the given file using a Boto 3 managed uploader, which will split up large
            # files automatically and upload parts in parallel.
            assert icd.file is not None  # For mypy
            assert self.bucket_name is not None  # For mypy
            assert self.s3_dest_folder is not None  # For mypy
            assert icd.sha256hash is not None  # For mypy
            self.s3.upload_file(icd.file, self.bucket_name, self.s3_dest_folder+icd.sha256hash)
            logger.info(f"File uploaded to S3 bucket: {icd.sha256hash}")

        except Exception as e:
            logger.warn(f"S3 exception: {e}")
