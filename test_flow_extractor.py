import datetime
import hashlib
import sys

import dpkt
from dpkt import http, UnpackError
from pcapfex.core.Streams.StreamBuilder import PcapIter
from pcap_extractor.FlowExtractor import FlowExtractor
from pcap_extractor.FlowBase import FlowBase
from pcap_extractor.TCPFlow import TCPFlow
from pcap_extractor.SMTPParser import SMTPParser
from pcap_extractor.POP3Parser import POP3Parser
from pcap_extractor.IMAPParser import IMAPParser
from pcap_extractor.HTTPParser import HTTPParser
import os
from io import BytesIO
from contextlib import closing


def dealStream(stream: TCPFlow):
    smtpParser = SMTPParser()
    pop3Parser = POP3Parser()
    imapParser = IMAPParser()
    httpParser = HTTPParser()
    forwardBytes, reverseBytes = stream.getAllForwardBytes(), stream.getAllReverseBytes()
    
    # parse http
    # 尝试从中解析出 http 请求信息
    httpRes = httpParser.parse(forwardBytes, reverseBytes)
    if len(httpRes) > 0:
        print(httpRes)

    if stream.dstPort == 39165:
        with open("test3.txt", "wb") as file:
            file.write(forwardBytes)
        with open("test4.txt", "wb") as file:
            file.write(reverseBytes)
    if stream.dstPort == 21:
        with open("test1.txt", "wb") as file:
            file.write(forwardBytes)
        with open("test2.txt", "wb") as file:
            file.write(reverseBytes)
    if stream.srcPort == 20 or stream.dstPort == 20:
        # 处理 FTP
        data1, data2 = forwardBytes, reverseBytes
        data = data1 if len(data2) == 0 else data2
        if len(data) > 0:
            md1 = hashlib.md5()
            md2 = hashlib.md5()
            md3 = hashlib.md5()
            with closing(BytesIO(data)) as data:
                for line in data.readlines():
                    md1.update(line)
                    if line.endswith(b"\r\n"):
                        md2.update(line[:-2])
                        md2.update(b'\r')
                        md3.update(line[:-2])
                        md3.update(b'\n')
            print(f"1: {md1.hexdigest()}")
            print(f"2: {md2.hexdigest()}")
            print(f"3: {md3.hexdigest()}")
    if stream.dstPort == 143:
        # 处理 IMAP
        print(imapParser.parse(forwardBytes, reverseBytes))
        with open("test1.txt", "wb") as file:
            file.write(forwardBytes)
        with open("test2.txt", "wb") as file:
            file.write(reverseBytes)
    if stream.dstPort == 110:
        reverseBytes = reverseBytes
        print(pop3Parser.parse(reverseBytes))
        # 处理 POP3
        # with open("test1.txt", "wb") as file:
        #     file.write(forwardBytes)
        # with open("test2.txt", "wb") as file:
        #     file.write(reverseBytes)
    if stream.dstPort == 25:
        data = forwardBytes
        with open("test1.txt", "wb") as file:
            file.write(forwardBytes)
        with open("test2.txt", "wb") as file:
            file.write(reverseBytes)
        print(smtpParser.parse(data))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python test_flow_extractor.py <pcap file path>")
        exit(-1)
    pcapfile = sys.argv[1]

    flowExtractor = FlowExtractor(valueCallback=dealStream)
    start = datetime.datetime.now()
    with open(pcapfile, 'rb') as pcap:
        packets = dpkt.pcap.Reader(pcap)

        fileSize = float(os.path.getsize(pcapfile))
        progress = -1

        print('  Size of file %s: %.2f mb' % (pcapfile, fileSize / 1000000))
        for ts, buf in packets:
            ethPacket = dpkt.ethernet.Ethernet(buf)
            flowExtractor.addPacket(ethPacket, ts)
        flowExtractor.done()
    print(datetime.datetime.now() - start)
