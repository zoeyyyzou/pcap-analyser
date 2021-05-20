import json
from dpkt import ethernet, ip, netflow, tcp, udp
import csv
from pcap_extractor.Flow import Flow
from pcap_extractor.Extractor import Extractor


class FlowExtractor(Extractor):
    flowMap = {}

    def __init__(self, outputFile: str):
        self.outputFile = open(outputFile, "w")
        self.f_csv = csv.writer(self.outputFile)
        self.f_csv.writerow(["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "flow_duration",
                             "src_packets", "src_byte_count", "dst_packets", "dst_byte_count",
                             "http_request_method", "http_request_value", "http_request_version",
                             "http_request_header"])
        self.flowMap = {}

    def addPacket(self, ethPacket: ethernet.Ethernet, timestamp: int):
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
            if len(flow.http_requests) == 0:
                self.f_csv.writerow([flow.srcIP, flow.dstIP, flow.srcPort, flow.dstPort, flow.protocol, flow.startTime,
                                     flow.lastTime - flow.startTime,
                                     flow.totalForwardCount, flow.totalForwardBytes, flow.totalReverseCount,
                                     flow.totalReverseBytes,
                                     "", "", "", ""])
            else:
                i = 1
                # self.f_csv.writerow(
                #     [flow.srcIP, flow.dstIP, flow.srcPort, flow.dstPort, flow.protocol, flow.startTime,
                #      flow.lastTime - flow.startTime,
                #      flow.totalForwardCount, flow.totalForwardBytes, flow.totalReverseCount,
                #      flow.totalReverseBytes,
                #      http_req.method, http_req.uri, http_req.version, ""])
                for http_req in flow.http_requests:
                    if i == 1:
                        self.f_csv.writerow(
                            [flow.srcIP, flow.dstIP, flow.srcPort, flow.dstPort, flow.protocol, flow.startTime,
                             flow.lastTime - flow.startTime,
                             flow.totalForwardCount, flow.totalForwardBytes, flow.totalReverseCount,
                             flow.totalReverseBytes,
                             http_req.method, http_req.uri, http_req.version, json.dumps(http_req.headers)])
                    else:
                        self.f_csv.writerow(
                            ["", "", "", "", "", "",
                             "",
                             "", "", "",
                             "",
                             http_req.method, http_req.uri, http_req.version, json.dumps(http_req.headers)])
                    i -= 1
        self.outputFile.close()
