from enum import Enum, auto
from dpkt import ip, ethernet, tcp, udp, http, UnpackError, ip6
from dpkt.utils import mac_to_str, inet_to_str
from datetime import datetime


class PacketDirection(Enum):
    """
    表征网络流量的方向
    """
    UNKNOWN = auto()  # 未知
    FORWARD = auto()  # 正向
    REVERSE = auto()  # 反向


class Flow:
    startTime = 0  # 流起始时间
    lastTime = 0  # 最后一次更新的时间
    srcMacAddr = ""  # 源mac地址
    dstMacAddr = ""  # 目的mac地址
    srcIP = ""  # 源IP地址
    dstIP = ""  # 目的IP地址
    srcPort = 0  # 源端口
    dstPort = 0  # 目的端口
    category = ""  # 地址类型 "ipv4-addr" / "ipv6-addr"
    protocol = 0  # 协议

    forwardStr = ""  # 正向流字符串表示，例如 192.168.1.4:13853-192.168.1.5:80
    reverseStr = ""  # 反向流字符串表示，例如 192.168.1.5:80-192.168.1.4:13853

    # 统计值
    totalCount = 0  # 总的网络包的数量
    totalForwardCount = 0  # 总的正向网络包的数量
    totalReverseCount = 0  # 总的反向网络包的数量
    totalPayloadBytes = 0  # 总的 payload 字节数
    totalForwardBytes = 0  # 总的正向的 payload 字节数
    totalReverseBytes = 0  # 总的反向的 payload 字节数

    http_requests = []

    def __init__(self, ethPacket: ethernet.Ethernet, timestamp: int):
        self.http_requests = []
        if not Flow.canBeMarkAsFlow(ethPacket):
            # 如果不是TCP或者UDP包，则忽略
            return
        self.startTime = timestamp
        self.srcMacAddr = mac_to_str(ethPacket.src)
        self.dstMacAddr = mac_to_str(ethPacket.dst)

        # 开始提取IP信息
        ipPacket = ethPacket.data
        self.srcIP = inet_to_str(ipPacket.src)
        self.dstIP = inet_to_str(ipPacket.dst)

        if isinstance(ipPacket, ip.IP):
            self.protocol = ipPacket.p
            self.category = "ipv4-addr"
        else:
            self.protocol = ipPacket.nxt
            self.category = "ipv6-addr"

        if self.protocol == ip.IP_PROTO_TCP and isinstance(ipPacket.data, tcp.TCP):
            # TCP 包
            tcpPacket = ipPacket.data
            self.srcPort = tcpPacket.sport
            self.dstPort = tcpPacket.dport
        elif self.protocol == ip.IP_PROTO_UDP and isinstance(ipPacket.data, udp.UDP):
            # UDP包
            udpPacket = ipPacket.data
            self.srcPort = udpPacket.sport
            self.dstPort = udpPacket.dport

        # 保存当前网络流的正反方向字符串表示
        self.forwardStr = f"{self.srcIP}:{self.srcPort}-{self.dstIP}:{self.dstPort}"
        self.reverseStr = f"{self.dstIP}:{self.dstPort}-{self.srcIP}:{self.srcPort}"

        # 调用 addPacket 添加第一个这个网络流的第一个网络包
        self.addPacket(ethPacket, timestamp)

    def addPacket(self, ethPacket: ethernet.Ethernet, timestamp: int):
        """
        往某个网络流里面添加一个属于该流的 TCP/UDP 包
        :param ethPacket:
        :param timestamp:
        :return:
        """
        # 如果不是TCP或者UDP包，则忽略
        if not Flow.canBeMarkAsFlow(ethPacket):
            return

        ipPacket = ethPacket.data
        # 如果不属于这个网络流，则忽略
        direction = self.getDirection(ethPacket)
        if direction == PacketDirection.UNKNOWN:
            return
        elif direction == PacketDirection.FORWARD:
            # 属于正向流
            self.totalForwardCount += 1
            if ipPacket.data.data:
                self.totalForwardBytes += len(ipPacket.data.data)
            if isinstance(ipPacket.data, tcp.TCP):
                tcpPacket = ipPacket.data
                try:
                    http_req = http.Request(tcpPacket.data)
                    self.http_requests.append(http_req)
                except UnpackError:
                    pass
        else:
            # 属于反向流
            self.totalReverseCount += 1
            if ethPacket.data.data.data:
                self.totalReverseBytes += len(ethPacket.data.data.data)

        self.lastTime = timestamp

        # 静态统计相关
        self.totalCount += 1
        if ethPacket.data.data.data:
            self.totalPayloadBytes += len(ethPacket.data.data.data)

        # 尝试解析成HTTP

    def getDirection(self, ethPacket: ethernet.Ethernet) -> PacketDirection:
        """
        判断某个以太网包属于哪个方向（如果不属于这条流，则返回 UNKNOWN）
        :param ethPacket:
        :return:
        """
        packetStr = Flow.encodeToStr(ethPacket)
        if packetStr == self.forwardStr:
            return PacketDirection.FORWARD
        elif packetStr == self.reverseStr:
            return PacketDirection.REVERSE
        return PacketDirection.UNKNOWN

    @staticmethod
    def encodeToStr(ethPacket: ethernet.Ethernet):
        """
        将 TCP/UDP 包 编码成字符串表示，格式如下：
        <源ip>:<源端口>-<目的ip>:<目的端口>
        例如：
            192.168.1.4:13853-192.168.1.5:80
        :param ethPacket:
        :return:
        """
        # 开始提取IP信息
        ipPacket = ethPacket.data
        srcIP = inet_to_str(ipPacket.src)
        dstIP = inet_to_str(ipPacket.dst)

        return f"{srcIP}:{ipPacket.data.sport}-{dstIP}:{ipPacket.data.dport}"

    @staticmethod
    def encodeToReverseStr(ethPacket: ethernet.Ethernet):
        # 开始提取IP信息
        ipPacket = ethPacket.data
        srcIP = inet_to_str(ipPacket.src)
        dstIP = inet_to_str(ipPacket.dst)
        return f"{dstIP}:{ipPacket.data.dport}-{srcIP}:{ipPacket.data.sport}"

    @staticmethod
    def canBeMarkAsFlow(ethPacket: ethernet.Ethernet):
        """
        判断收到的一个以太网包里面存放的是不是 TCP/UDP 包
        1. 如果是 TCP/UDP 包，则可以将其标识为一个网络流;
        2. 如果不是，则不能标记为网络流
        :param ethPacket:
        :return:
        """
        if isinstance(ethPacket.data, ip.IP):
            # 如果是 IPv4 包
            return ethPacket.data.p == ip.IP_PROTO_TCP or ethPacket.data.p == ip.IP_PROTO_UDP
        elif isinstance(ethPacket.data, ip6.IP6):
            return ethPacket.data.nxt == ip.IP_PROTO_TCP or ethPacket.data.nxt == ip.IP_PROTO_UDP
        else:
            return False

    def toFlowRecord(self):
        if self.protocol == ip.IP_PROTO_TCP:
            protocolStr = "tcp"
        else:
            protocolStr = "udp"
        return {
            "src_ip": self.srcIP,
            "dst_ip": self.dstIP,
            "src_port": self.srcPort,
            "dst_port": self.dstPort,
            "type": self.category,
            "protocol": protocolStr,
            "start_time": datetime.fromtimestamp(self.startTime),
            "end_time": datetime.fromtimestamp(self.lastTime),
            "src_packets": self.totalForwardCount,
            "src_byte_count": self.totalForwardBytes,
            "dst_packets": self.totalReverseCount,
            "dst_byte_count": self.totalReverseBytes,
        }
