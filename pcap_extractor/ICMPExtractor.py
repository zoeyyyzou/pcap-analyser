from pcap_extractor.Extractor import Extractor
from dpkt import ethernet, ip, icmp
from dpkt.utils import inet_to_str


class ICMPExtractor(Extractor):
    def __init__(self, valueCallback):
        super().__init__(valueCallback)

    def addPacket(self, packetNumber, ethPacket: ethernet.Ethernet, timestamp: float):
        # 过滤一下，我们只处理ICMP包
        if not (isinstance(ethPacket.data, ip.IP) and isinstance(ethPacket.data.data, icmp.ICMP)):
            return
        ipPacket = ethPacket.data
        icmpPacket = ipPacket.data
        self.valueCallback({
            "src_ip": inet_to_str(ipPacket.src),
            "dst_ip": inet_to_str(ipPacket.dst),
            "icmp_type": icmpPacket.type,
            "icmp_code": icmpPacket.code
        })

    def done(self):
        pass
