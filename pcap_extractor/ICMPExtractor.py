from pcap_extractor.Extractor import Extractor
from dpkt import ethernet, ip, icmp
from dpkt.utils import inet_to_str
import csv


class ICMPExtractor(Extractor):
    def __init__(self, outputFile):
        self.outputFile = open(outputFile, "w")
        self.f_csv = csv.writer(self.outputFile)
        self.f_csv.writerow(
            ["src_ip", "dst_ip", "icmp_type_hex", "icmp_type", "icmp_code_hex", "icmp_code", "timestamp"])

    def addPacket(self, ethPacket: ethernet.Ethernet, timestamp: int):
        # 过滤一下，我们只处理ICMP包
        if not (isinstance(ethPacket.data, ip.IP) and isinstance(ethPacket.data.data, icmp.ICMP)):
            return
        ipPacket = ethPacket.data
        icmpPacket = ipPacket.data
        self.f_csv.writerow([inet_to_str(ipPacket.src), inet_to_str(ipPacket.dst), hex(icmpPacket.type),
                             icmpPacket.type, str(hex(icmpPacket.code)), icmpPacket.code, timestamp])

    def done(self):
        self.outputFile.close()
