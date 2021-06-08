import datetime

import dpkt
from pcap_extractor.FileScanner import FileScanner
from pcapfex.core.Streams.StreamBuilder import PcapIter
from pcap_extractor.FlowExtractor import FlowExtractor
from pcap_extractor.FlowBase import FlowBase
from pcap_extractor.SMTPParser import SMTPParser
from pcap_extractor.POP3Parser import POP3Parser
import os
from io import BytesIO
from contextlib import closing

fileScanner = FileScanner(False)


def dealStream(stream: FlowBase):
    smtpParser = SMTPParser()
    pop3Parser = POP3Parser()
    if stream.dstPort == 110:
        reverseBytes = stream.getAllReverseBytes()
        print("lala")
        print(pop3Parser.parse(reverseBytes))
        # # 处理 POP3
        # with open("test1.txt", "wb") as file:
        #     file.write(forwardBytes)
        # with open("test2.txt", "wb") as file:
        #     file.write(reverseBytes)
    if stream.dstPort == 25:
        data = stream.getAllForwardBytes()
        print(smtpParser.parse(data))
    #     with open("test1.txt", "wb") as file:
    #         file.write(data)
        # with closing(BytesIO(data)) as data:
        #     line = data.readline()
        #     while line not in [b'']:
        #         print(line)
                # keyVal = line.split(b':')
                # if len(keyVal) < 2:
                #     line = data.readline()
                #     continue
                # val = b':'.join(keyVal[1:]).strip()
                # print(keyVal[0], " => ", val)
                # line = data.readline()
    # elif stream.srcPort == 25:
    #     pass
        # data = stream.getAllBytes()
        # with open("test2.txt", "wb") as file:
        #     file.write(data)
        # with closing(BytesIO(data)) as data:
        #     line = data.readline()
        #     while line not in [b'']:
        #         print(line)
        #         # keyVal = line.split(b':')
        #         # if len(keyVal) < 2:
        #         #     line = data.readline()
        #         #     continue
        #         # val = b':'.join(keyVal[1:]).strip()
        #         # print(keyVal[0], " => ", val)
        #         line = data.readline()
        # pass
        # print(stream.getAllBytes())
    # result = fileScanner.findFile(stream)
    # if len(result) > 0:
    #     print(len(result))


if __name__ == '__main__':
    pcapfile = "pop3.pcap"
    flowExtractor = FlowExtractor(valueCallback=dealStream)
    start = datetime.datetime.now()
    with open(pcapfile, 'rb') as pcap:
        dpkt.pcap.Reader.__iter__ = PcapIter
        packets = dpkt.pcap.Reader(pcap)
        capLenError = False

        fileSize = float(os.path.getsize(pcapfile))
        progress = -1

        print('  Size of file %s: %.2f mb' % (pcapfile, fileSize / 1000000))
        for packetNumber, (ts, complete, buf) in enumerate(packets, 1):
            if not complete:
                continue
            ethPacket = dpkt.ethernet.Ethernet(buf)
            flowExtractor.addPacket(packetNumber, ethPacket, ts)
        flowExtractor.done()
    print(datetime.datetime.now() - start)
