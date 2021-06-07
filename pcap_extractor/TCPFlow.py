from dpkt import ip, ethernet, tcp, udp, http, UnpackError, ip6
from datetime import datetime
from pcap_extractor.FlowBase import FlowBase
from io import BytesIO
from contextlib import closing


class TCPFlow(FlowBase):
    """
    表示一个 TCP 流
    """

    def __init__(self, ethPacket: ethernet.Ethernet, timestamp: float):
        self.http_requests = []
        self.forwardPackets = dict()  # 一个字典，用来根据序列号记录正向TCP网络包
        self.reversePackets = dict()  # 一个字典，用来根据序列号记录反向TCP网络包
        self.forwardClosed = False  # 正向流是否关闭
        self.reverseClosed = False  # 反向流是否关闭
        super().__init__(ethPacket, timestamp)

    def addForwardPacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        """
        添加一个正向网络包
        :param ethPacket:
        :param timestamp:
        :return:
        """
        # 如果不是TCP或者UDP包，则忽略
        if not FlowBase.canBeMarkAsFlow(ethPacket):
            return
        super(TCPFlow, self)._addForwardPacket(ethPacket, timestamp)

        tcpPacket = ethPacket.data.data

        if len(tcpPacket.data) == 0:
            return

        # 将TCP包存到字典里面，后面再对网络包进行排序可以还原TCP流的内容
        if tcpPacket.seq not in self.forwardPackets:
            self.forwardPackets[tcpPacket.seq] = tcpPacket

        # 尝试从中解析出 http 请求信息
        try:
            http_req = http.Request(tcpPacket.data)
            self.http_requests.append(http_req)
        except UnpackError:
            pass

    def addReversePacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        """
        添加一个反向网络包
        :param ethPacket:
        :param timestamp:
        :return:
        """
        # 如果不是TCP或者UDP包，则忽略
        if not FlowBase.canBeMarkAsFlow(ethPacket):
            return
        super(TCPFlow, self)._addReversePacket(ethPacket, timestamp)

        tcpPacket = ethPacket.data.data

        if len(tcpPacket.data) == 0:
            return

        # 将TCP包存到字典里面，后面再对网络包进行排序可以还原TCP流的内容
        if tcpPacket.seq not in self.reversePackets:
            self.reversePackets[tcpPacket.seq] = tcpPacket

    def getAllForwardBytes(self) -> bytes:
        """
        返回所有正向流的集合
        :return:
        """
        with closing(BytesIO()) as byteBuffer:
            for packet in self.forwardIter():
                byteBuffer.write(packet.data)
            return byteBuffer.getvalue()

    def getAllReverseBytes(self) -> bytes:
        """
        返回所有反向流的集合
        :return:
        """
        with closing(BytesIO()) as byteBuffer:
            for packet in self.reverseIter():
                byteBuffer.write(packet.data)
            return byteBuffer.getvalue()

    def forwardIter(self):
        """
        自定义正向流迭代器，按序列号顺序遍历当前 TCP 流的所有的 TCP 包
        :return:
        """
        sortedPackets = sorted(list(self.forwardPackets.values()), key=lambda v: v.seq)
        for packet in sortedPackets:
            yield packet

    def reverseIter(self):
        """
        自定义反向流迭代器，按序列号顺序遍历当前 TCP 流的所有的 TCP 包
        :return:
        """
        sortedPackets = sorted(list(self.reversePackets.values()), key=lambda v: v.seq)
        for packet in sortedPackets:
            yield packet

    @staticmethod
    def _isValid(myIter):
        nextSeq = None
        for packet in myIter:
            if nextSeq is None:
                nextSeq = packet.seq + len(packet.data)
                continue
            if nextSeq != packet.seq:
                return False
            if len(packet.data) == 0:
                nextSeq += 1
            else:
                nextSeq += len(packet.data)
        return True

    def isForwardValid(self):
        """
        判断当前正向 TCP 流是否是有效的流
        :return:
        """
        if len(self.forwardPackets) == 0:
            return False
        if self.forwardClosed:
            return True
        return TCPFlow._isValid(self.forwardIter())

    def isReverseValid(self):
        """
        判断当前反向 TCP 流是否是有效的流
        :return:
        """
        if len(self.reversePackets) == 0:
            return False
        if self.reverseClosed:
            return True
        return TCPFlow._isValid(self.reverseIter())

    def isValid(self):
        """
        判断当前 TCP 流是否完整
        :return:
        """
        if not (self.forwardClosed and self.reverseClosed):
            return False
        return self.isForwardValid() and self.isReverseValid()

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
        }
