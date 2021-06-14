from abc import ABCMeta, abstractmethod
from dpkt import ip, ethernet, ip6, tcp, udp
from dpkt.utils import inet_to_str, mac_to_str


class FlowBase(metaclass=ABCMeta):
    """
    定义网络流（TCP流和UDP流的通用属性）
    Defines network flows (the common attributes of TCP flows and UDP flows)
    """
    startTime = 0  # 流起始时间flow starts time
    lastTime = 0  # 最后一次更新的时间flow last update time
    lastForwardTime = 0  # 最后一次抓取到正向包的时间Last time the forward packet was captured
    lastReverseTime = 0  # 最后一次抓取到反向包的时间Last time the reverse packet was captured
    # srcMacAddr = ""  # 源mac地址 Source MAC address
    # dstMacAddr = ""  # 目的mac地址 Destination MAC address
    srcIP = ""  # 源IP地址 Source IP address
    dstIP = ""  # 目的IP地址 Destination IP address
    srcPort = 0  # 源端口 Source port address
    dstPort = 0  # 目的端口 Source destination port address
    category = ""  # 地址类型 "ipv4-addr" / "ipv6-addr"
    protocol = 0  # 协议

    forwardStr = ""  # 正向流字符串表示，例如 6-192.168.1.4:13853-192.168.1.5:80 Forward flow
    reverseStr = ""  # 反向流字符串表示，例如 6-192.168.1.5:80-192.168.1.4:13853 Reverse flow

    # 统计值
    totalCount = 0  # 总的网络包的数量 Number of total packets
    totalForwardCount = 0  # 总的正向网络包的数量 Number of total forward packets
    totalReverseCount = 0  # 总的反向网络包的数量 Number of total reverse packets
    totalPayloadBytes = 0  # 总的 payload 字节数 Total payload bytes
    totalForwardBytes = 0  # 总的正向的 payload 字节数 Total forward payload bytes
    totalReverseBytes = 0  # 总的反向的 payload 字节数 Total reverse payload bytes

    def __init__(self, ethPacket: ethernet.Ethernet, timestamp: float):
        if not FlowBase.canBeMarkAsFlow(ethPacket):
            # 如果不是TCP或者UDP包，则忽略
            return
        self.startTime = timestamp
        # self.srcMacAddr = mac_to_str(ethPacket.src)
        # self.dstMacAddr = mac_to_str(ethPacket.dst)

        # 开始提取IP信息 Extract IP
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
        self.forwardStr = f"{FlowBase.getProtocol(ethPacket)}-{self.srcIP}:{self.srcPort}-{self.dstIP}:{self.dstPort}"
        self.reverseStr = f"{FlowBase.getProtocol(ethPacket)}-{self.dstIP}:{self.dstPort}-{self.srcIP}:{self.srcPort}"

        # 调用 addPacket 添加第一个这个网络流的第一个网络包
        self.addForwardPacket(ethPacket, timestamp)

    def _addForwardPacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        """
        在此处对 TCP 和 UDP 流的一些正向流的共性特征做提取和统计
        Extracting and analyzing the common characteristics of some forward flows in TCP and UDP flows
        :param ethPacket:
        :param timestamp:
        :return:
        """
        self.lastTime = timestamp
        self.lastForwardTime = timestamp

        # 静态统计相关 Static statistics
        self.totalCount += 1
        self.totalForwardCount += 1
        if ethPacket.data.data.data:
            self.totalPayloadBytes += len(ethPacket.data.data.data)
            self.totalForwardBytes += len(ethPacket.data.data.data)

    def _addReversePacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        """
        在此处对 TCP 和 UDP 流的一些反向流的共性特征做提取和统计
        :param ethPacket:
        :param timestamp:
        :return:
        """
        self.lastTime = timestamp
        self.lastReverseTime = timestamp

        # 静态统计相关
        self.totalCount += 1
        self.totalReverseCount += 1
        if ethPacket.data.data.data:
            self.totalPayloadBytes += len(ethPacket.data.data.data)
            self.totalReverseBytes += len(ethPacket.data.data.data)

    @abstractmethod
    def addForwardPacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        pass

    @abstractmethod
    def addReversePacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        pass

    @abstractmethod
    def getAllForwardBytes(self) -> bytes:
        """
        获取正向流的所有字节数据
        Gets all forward byte data
        :return:
        """
        pass

    @abstractmethod
    def getAllReverseBytes(self) -> bytes:
        """
        获取反向流的所有字节数据
        Gets all reverse byte data
        :return:
        """
        pass

    @staticmethod
    def getProtocol(ethPacket: ethernet.Ethernet):
        """
        提取 IPv6 和 IPv4 包中的协议字段
        Extract protocol fields in IPv6 and IPv4 packets
        :param ethPacket:
        :return:
        """
        ipPacket = ethPacket.data
        if isinstance(ipPacket, ip.IP):
            return ipPacket.p
        elif isinstance(ipPacket, ip6.IP6):
            return ipPacket.nxt
        return 0

    @staticmethod
    def encodeToStr(ethPacket: ethernet.Ethernet):
        """
        将 TCP/UDP 包 编码成字符串表示，格式如下：<协议>-<源ip>:<源端口>-<目的ip>:<目的端口> E.g：6-192.168.1.4:13853-192.168.1.5:80
        Encode the TCP/UDP packet into a string representation, the format is as follows:
        <protocol>-<source ip>:<source port>-<destination ip>:<destination port>
        :param ethPacket:
        :return:
        """
        # 开始提取IP信息
        ipPacket = ethPacket.data
        srcIP = inet_to_str(ipPacket.src)
        dstIP = inet_to_str(ipPacket.dst)
        return f"{FlowBase.getProtocol(ethPacket)}-{srcIP}:{ipPacket.data.sport}-{dstIP}:{ipPacket.data.dport}"

    @staticmethod
    def encodeToReverseStr(ethPacket: ethernet.Ethernet):
        # 开始提取IP信息
        ipPacket = ethPacket.data
        srcIP = inet_to_str(ipPacket.src)
        dstIP = inet_to_str(ipPacket.dst)
        return f"{FlowBase.getProtocol(ethPacket)}-{dstIP}:{ipPacket.data.dport}-{srcIP}:{ipPacket.data.sport}"

    @staticmethod
    def canBeMarkAsFlow(ethPacket: ethernet.Ethernet):
        """
        判断收到的一个以太网包里面存放的是不是 TCP/UDP 包
        1. 如果是 TCP/UDP 包，则可以将其标识为一个网络流;
        2. 如果不是，则不能标记为网络流
        Determine is there TCP/UDP packet in an Ethernet packet. If yes, identifies it as a network flow
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
