import datetime
import hashlib

import dpkt
from pcapfex.core.Streams.StreamBuilder import PcapIter
from pcap_extractor.FlowExtractor import FlowExtractor
from pcap_extractor.FlowBase import FlowBase
from pcap_extractor.SMTPParser import SMTPParser
from pcap_extractor.POP3Parser import POP3Parser
from pcap_extractor.IMAPParser import IMAPParser
import os
from io import BytesIO
from contextlib import closing


def dealStream(stream: FlowBase):
    smtpParser = SMTPParser()
    pop3Parser = POP3Parser()
    imapParser = IMAPParser()
    if stream.srcPort == 20 or stream.dstPort == 20:
        # 处理 FTP
        data1, data2 = stream.getAllForwardBytes(), stream.getAllReverseBytes()
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
        print(imapParser.parse(stream.getAllForwardBytes(), stream.getAllReverseBytes()))
        with open("test1.txt", "wb") as file:
            file.write(stream.getAllForwardBytes())
        with open("test2.txt", "wb") as file:
            file.write(stream.getAllReverseBytes())
    if stream.dstPort == 110:
        reverseBytes = stream.getAllReverseBytes()
        print(pop3Parser.parse(reverseBytes))
        # 处理 POP3
        # with open("test1.txt", "wb") as file:
        #     file.write(stream.getAllForwardBytes())
        # with open("test2.txt", "wb") as file:
        #     file.write(stream.getAllReverseBytes())
    if stream.dstPort == 25:
        data = stream.getAllForwardBytes()
        # with open("test1.txt", "wb") as file:
        #     file.write(stream.getAllForwardBytes())
        # with open("test2.txt", "wb") as file:
        #     file.write(stream.getAllReverseBytes())
        print(smtpParser.parse(data))


if __name__ == '__main__':
    pcapfile = "imap.pcap"
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
