from dpkt import ethernet

from pcapfex.core.FileScanner import FileScanner, FileObject
from pcap_extractor.Extractor import Extractor
from datetime import datetime


class FileHashObject:
    def __init__(self, fileObject: FileObject):
        self.src = fileObject.source
        self.dst = fileObject.destination
        self.type = fileObject.fileEnding
        self.size = fileObject.size
        self.ts = fileObject.timestamp
        self.md5 = fileObject.md5
        self.sha1 = fileObject.sha1
        self.sha256 = fileObject.sha256

    def toDict(self):
        return {
            "src": self.src,
            "dst": self.dst,
            "file_type": self.type,
            "size": self.size,
            "timestamp": datetime.fromtimestamp(self.ts),
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
        }


class FileHashExtractor(Extractor):
    def __init__(self, valueCallback):
        super().__init__(valueCallback)
        self.fileScanner = FileScanner(fileObjectCallback=self._dealFileObject)

    def _dealFileObject(self, fileObject: FileObject):
        self.valueCallback(FileHashObject(fileObject))

    def addPacket(self, packetNumber: int, ethPacket: ethernet.Ethernet, timestamp: float):
        self.fileScanner.addPacket(packetNumber, timestamp, ethPacket)

    def done(self):
        self.fileScanner.done()
