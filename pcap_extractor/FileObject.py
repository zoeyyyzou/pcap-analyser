import hashlib
from pcap_extractor.FlowBase import FlowBase


class FileObject(object):
    def __init__(self, data, flow: FlowBase):
        self.data = data
        self.md5 = hashlib.md5(data).hexdigest()
        self.sha1 = hashlib.sha1(data).hexdigest()
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.size = len(data)
        self.srcIP = flow.srcIP
        self.dstIP = flow.dstIP
        self.srcPort = flow.srcPort
        self.dstPort = flow.dstPort
        self.timestamp = flow.startTime
        self.fileEncoding = ""
        self.fileType = ""
