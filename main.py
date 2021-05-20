import PySimpleGUI as sg
import os
import dpkt
from pcap_extractor.FlowExtractor import FlowExtractor
from pcap_extractor.DNSExtractor import DNSExtractor, DNSRecord
from pcap_extractor.ICMPExtractor import ICMPExtractor
from sqlalchemy import create_engine, text, or_
from sqlalchemy.orm import sessionmaker
from entity.cctx import Address, Domain, Initial, Report, DomainRecord, FlowRecord
from datetime import datetime


def getEngine():
    engine = create_engine("sqlite+pysqlite:///cctx.db", echo=False, future=True)

    # # sqlite3 开启外键约束
    # with engine.connect() as conn:
    #     conn.execute(text("pragma foreign_keys=on"))

    Initial(engine)

    return engine


class PcapAnalyser:
    def __init__(self):
        self.session = None
        self.report = None

    def dealICMPValue(self, value: dict):
        """
        处理 ICMP 包的解析结果
        :param value:
        :return:
        """
        pass

    def dealDNSValue(self, value: dict):
        """
        处理提取到的 DNS 记录
        :param value:
        :return:
        """
        # 提取到DNS记录
        dr = DomainRecord(**value)
        self.report.total_domain_num += 1
        # 检索数据库，如果有想关联的 Observable，就存到report当中，如果没有，则忽略
        observables = self.session.query(Domain). \
            filter(Domain.value == dr.domain). \
            all()
        if len(observables) > 0:
            dr.observables = observables
            self.report.domain_records.append(dr)

    def dealFlowValue(self, value: dict):
        # 填充 FlowRecord
        record = FlowRecord(**value)
        self.report.total_flow_num += 1
        # 检索数据库，如果有相关联的 Observable，就存到report当中，如果没有，则忽略
        observables = self.session.query(Address). \
            filter(or_(Address.value == value['src_ip'], Address.value == value['dst_ip'])). \
            all()
        # 如果没有相关联的 Observable，则忽略掉
        if len(observables) <= 0:
            return

        record.observables = observables
        self.report.flow_records.append(record)
        # if flow.lastTime > report.end_time:
        #     report.end_time = flow.lastTime

    def dealPcapFile(self, inputFile: str, progressCallback):
        """
            解析 pcap 文件，提取特征
            :param inputFile:
            :return:
            """
        f = open(inputFile, "rb")
        totalSize = os.path.getsize(inputFile)
        pcap = dpkt.pcap.Reader(f)

        # 获取数据库session
        engine = getEngine()
        DBSession = sessionmaker(bind=engine)
        self.session = DBSession()

        # 将对比的特征生成报告
        self.report = Report(title=f"{f.name} report", description="",
                             total_domain_num=0,
                             total_packet_num=0,
                             total_flow_num=0)

        extractors = [
            FlowExtractor(self.dealFlowValue),
            ICMPExtractor(self.dealICMPValue),
            DNSExtractor(self.dealDNSValue),
        ]
        startTime = None
        preProgress = 0
        progressCallback(preProgress)
        for ts, buf in pcap:
            currentProgress = int(f.tell() * 100 / totalSize)
            if currentProgress != preProgress:
                progressCallback(currentProgress)
                preProgress = currentProgress
            if not startTime:
                startTime = ts
                self.report.start_time = datetime.fromtimestamp(startTime)
                self.report.end_time = self.report.start_time
            self.report.total_packet_num += 1

            ethPacket = dpkt.ethernet.Ethernet(buf)
            for extractor in extractors:
                extractor.addPacket(ethPacket, ts)

        for extractor in extractors:
            extractor.done()

        self.session.add(self.report)
        self.session.commit()

        # output report
        outputStr = f"Report title: {self.report.title}"
        outputStr += f"\ntotal_packet_num: {self.report.total_packet_num}"
        outputStr += f"\ntotal_flow_num: {self.report.total_flow_num} / match_flow_num: {len(self.report.flow_records)}"
        outputStr += f"\ntotal_domain_num: {self.report.total_domain_num} / match_domain_num: {len(self.report.domain_records)}"
        self.session.close()
        self.session = None
        self.report = None
        return outputStr


if __name__ == '__main__':
    sg.theme("Light Green")

    # create window
    window = sg.Window("Pcap Analyser", [
        [sg.Text("Please enter a pcap file path")],
        [sg.In(key="inputPcapPath"), sg.FileBrowse(key='selectPcapFileBrowse', target='inputPcapPath')],
        [sg.ProgressBar(100, key="analyse-progress")],
        [sg.Button("analyse")],
    ])

    inputPcapPath = window["inputPcapPath"]
    progressBar = window["analyse-progress"]

    pcapAnalyser = PcapAnalyser()
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Cancel':  # if user closes window or clicks cancel
            break
        elif event == "analyse":
            path = values["inputPcapPath"]
            if not os.path.exists(path):
                sg.popup_error("File not exists!")
            else:
                # text = sg.popup_get_file("Please select a pcap file", no_window=True)
                res = pcapAnalyser.dealPcapFile(path, lambda progress: progressBar.update_bar(progress))
                sg.popup_ok(res)

    window.close()
