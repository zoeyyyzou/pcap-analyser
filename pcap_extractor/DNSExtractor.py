from pcap_extractor.Extractor import Extractor
from dpkt import ethernet, dns, ip, udp
from dpkt.utils import inet_to_str
from datetime import datetime


class DNSRecord:
    domain = ""
    domain_type = ""
    value = ""
    timestamp = 0

    def __init__(self, values):
        self.domain = values[0]
        self.domain_type = values[1]
        self.value = values[2]
        self.timestamp = values[3]

    def toDomainRecord(self):
        return {
            "domain": self.domain,
            "domain_type": self.domain_type,
            "value": self.value,
            "timestamp": datetime.fromtimestamp(self.timestamp)
        }


class DNSExtractor(Extractor):

    def __init__(self, valueCallback):
        super().__init__(valueCallback)

    def addPacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        # DNS 采用UDP通信，不是UDP包忽略
        if not (isinstance(ethPacket.data, ip.IP) and isinstance(ethPacket.data.data, udp.UDP)):
            return
        ipPacket = ethPacket.data
        udpPacket = ipPacket.data
        if udpPacket.sport == 53:
            # 源端口是53，表示是域名服务器返回的 Response
            dnsPacket = dns.DNS(udpPacket.data)

            # 下面几种section的含义，参考这个链接：http://www.ruanyifeng.com/blog/2016/06/dns.html
            for rr in dnsPacket.qd:
                # question section
                pass
            for rr in dnsPacket.an:
                # answer section
                self.decodeDNSResponse(rr, timestamp)
            for rr in dnsPacket.ns:
                # authority section
                pass
            for rr in dnsPacket.ar:
                # addition section
                pass

    def decodeDNSResponse(self, rr: dns.DNS.RR, timestamp: float):
        if rr.type == dns.DNS_A:
            # A 记录 => ipv4
            self.valueCallback(DNSRecord([rr.name, "A", inet_to_str(rr.rdata), timestamp]).toDomainRecord())
        elif rr.type == dns.DNS_AAAA:
            # AAAA 记录 => ipv6
            self.valueCallback(DNSRecord([rr.name, "AAAA", inet_to_str(rr.rdata), timestamp]).toDomainRecord())

    def done(self):
        pass
