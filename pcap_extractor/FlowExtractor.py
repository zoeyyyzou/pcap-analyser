from dpkt import ethernet
from pcap_extractor.Flow import Flow
from pcap_extractor.Extractor import Extractor


class FlowExtractor(Extractor):
    flowMap = {}

    def __init__(self, valueCallback):
        super().__init__(valueCallback)
        self.flowMap = {}

    def addPacket(self, packetNumber, ethPacket: ethernet.Ethernet, timestamp: float):
        # 只处理 TCP 和 UDP 包，其它包直接忽略（同时支持处理 IPv4 和 IPv6）
        if not Flow.canBeMarkAsFlow(ethPacket):
            return
        # 用四元组（源IP，源端口，目的IP，目的端口标识一条流）
        key = Flow.encodeToStr(ethPacket)
        reverseKey = Flow.encodeToReverseStr(ethPacket)

        # 判断是否已经前面有该流量的记录
        if key in self.flowMap:
            self.flowMap[key].addPacket(ethPacket, timestamp)
        elif reverseKey in self.flowMap:
            self.flowMap[reverseKey].addPacket(ethPacket, timestamp)
        else:
            self.flowMap[key] = Flow(ethPacket, timestamp)

    def done(self):
        for key in self.flowMap:
            flow = self.flowMap[key]
            self.valueCallback(flow)
