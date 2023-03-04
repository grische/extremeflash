"""Module providing a TFTP server"""

import logging
import os.path
import tempfile
from os import listdir
from pathlib import Path
from shutil import copyfile
from threading import Thread

import tftpy


class TftpServer:
    """Class handling the tftp server"""

    def __init__(self, filepath: str, listenip: str = "0.0.0.0", port: int = 69):
        # pylint: disable=consider-using-with
        self.tmpdir = tempfile.TemporaryDirectory()
        self.filepath = Path(filepath)
        self.listenip = listenip
        self.port = port
        self.tftp_server = tftpy.TftpServer(self.tmpdir.name)
        self.tftp_thread = Thread(target=self.tftp_server.listen, args=[self.listenip, self.port])
        copyfile(self.filepath, os.path.join(self.tmpdir.name, self.filepath.name))

    def start(self) -> tftpy.TftpServer:
        logging.info(f"Starting tftp server on {self.listenip}:{self.port} from {self.tmpdir}")

        logging.debug(f"Files in ${self.tmpdir}: {listdir(self.tmpdir.name)}")
        self.tftp_thread.start()
        return self.tftp_thread

    def is_alive(self) -> bool:
        return self.tftp_thread.is_alive() if self.tftp_thread is not None else False

    def stop(self):
        if self.is_alive():
            self.tftp_server.stop()

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        self.tmpdir.cleanup()
