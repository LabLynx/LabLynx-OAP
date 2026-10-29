# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""A local S3-compatible stand-in for the OCC's store tests. Never a cloud account.

    with LocalS3(moto_server_path) as s3:      # s3.endpoint, s3.access_key, s3.secret_key
        ...

It runs moto's server (moto, Apache-2.0, installed in its own virtual environment, never in the
OCC's) on 127.0.0.1 on a free port, waits until it answers, and stops it by its process id
afterwards. OCC_TEST_MOTO names the moto_server program; without it the S3 tests are skipped.
"""
import os
import signal
import socket
import subprocess
import time
import urllib.request


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalS3:
    access_key = "occ-test-access"
    secret_key = "occ-test-secret-not-a-real-one"

    def __init__(self, program):
        self.program = program
        self.proc = None

    def __enter__(self):
        port = _free_port()
        self.endpoint = "http://127.0.0.1:%d" % port
        self.proc = subprocess.Popen([self.program, "-H", "127.0.0.1", "-p", str(port)], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                urllib.request.urlopen(self.endpoint + "/moto-api/", timeout=1).read()
                return self
            except Exception:                                            # noqa: BLE001
                time.sleep(0.2)
        self.__exit__()
        raise RuntimeError("the S3 stand-in did not start")

    def __exit__(self, *a):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc = None
