import PySimpleGUI as sg
import os
import dpkt
from pcap_extractor.FlowExtractor import FlowExtractor
from pcap_extractor.DNSExtractor import DNSExtractor, DNSRecord
from pcap_extractor.ICMPExtractor import ICMPExtractor
from pcap_extractor.FileHashExtractor import FileHashRecord, FileHashExtractor
from pcap_extractor.Flow import Flow
from sqlalchemy import create_engine, text, or_
from sqlalchemy.orm import sessionmaker
from entity.cctx import Address, Domain, Initial, Report, DomainRecord, FlowRecord
from datetime import datetime
from pcapfex.core.Streams.StreamBuilder import PcapIter


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

    def dealFlowValue(self, flow: Flow):
        value = flow.toFlowRecord()
        # 输出 URL
        for http_req in flow.http_requests:
            print(f"http://{http_req.headers['host']}{http_req.uri}")
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

    def dealFileHashValue(self, fileHashRecord: FileHashRecord):
        pass

    def dealPcapFile(self, inputFile: str, progressCallback):
        """
            解析 pcap 文件，提取特征
            :param inputFile:
            :return:
            """
        # 获取数据库session
        engine = getEngine()
        DBSession = sessionmaker(bind=engine)
        self.session = DBSession()

        # 将对比的特征生成报告
        self.report = Report(title=f"{inputFile} report", description="",
                             total_domain_num=0,
                             total_packet_num=0,
                             total_flow_num=0)

        extractors = [
            FlowExtractor(self.dealFlowValue),
            ICMPExtractor(self.dealICMPValue),
            DNSExtractor(self.dealDNSValue),
            FileHashExtractor(self.dealFileHashValue)
        ]
        startTime = None
        preProgress = 0
        progressCallback(preProgress)
        totalSize = os.path.getsize(inputFile)
        with open(inputFile, 'rb') as pcap:
            dpkt.pcap.Reader.__iter__ = PcapIter
            packets = dpkt.pcap.Reader(pcap)
            for packetNumber, (ts, complete, buf) in enumerate(packets, 1):
                currentProgress = int(pcap.tell() * 100 / totalSize)
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
                    extractor.addPacket(packetNumber, ethPacket, ts)

        for extractor in extractors:
            extractor.done()

        self.session.add(self.report)
        self.session.commit()
        print(f"title: {self.report.title} => {self.report.id}")
        self.session.refresh(self.report)
        self.session.expunge(self.report)
        self.session.close()
        self.session = None
        print(f"title: {self.report.title} => {self.report.id}")
        return self.report.id


def makeWindow1():
    return sg.Window("Pcap Analyser", [
        [sg.Text("Please enter a pcap file path")],
        [sg.In(key="inputPcapPath", size=(30, 100)), sg.FileBrowse(key='selectPcapFileBrowse', target='inputPcapPath')],
        [sg.ProgressBar(100, orientation='h', size=(28, 5), key="analyse-progress")],
        [sg.Button("analyse")],
    ], finalize=True)


def makeReportTableWindow(report: Report):
    matchFlowValues = []
    for flowRecord in report.flow_records:
        matchFlowValues.append([flowRecord.src_ip, flowRecord.dst_ip, flowRecord.src_port, flowRecord.dst_port,
                                flowRecord.type, flowRecord.protocol, flowRecord.src_packets, flowRecord.dst_packets])
    matchDomains = []
    for domainRecord in report.domain_records:
        matchDomains.append([domainRecord.domain, domainRecord.domain_type, domainRecord.value])

    outputStr = f"Report title: {report.title}"
    outputStr += f"\ntotal_packet_num: {report.total_packet_num}"
    outputStr += f"\ntotal_flow_num: {report.total_flow_num} / match_flow_num: {len(report.flow_records)}"
    outputStr += f"\ntotal_domain_num: {report.total_domain_num} / match_domain_num: {len(report.domain_records)}\n\n"
    layout = [
        [sg.Text(outputStr, font=('微软雅黑', 12))],
    ]
    if len(report.flow_records) > 0:
        layout.append(
            [sg.Text("Match flows:")],
        )
        layout.append(
            [sg.Table(
                values=matchFlowValues,
                headings=["src_ip", "dst_ip", "src_port", "dst_port", "type", "protocol", "src_packets",
                          "dst_packets"],
                auto_size_columns=True,  # 自动调整列宽（根据上面第一次的values默认值为准，update时不会调整）
                display_row_numbers=True,  # 序号
                justification='center',
                font=('微软雅黑', 12),
                text_color='black',
                background_color='white',
                enable_events=True,
                bind_return_key=True,
                tooltip='This is a table'
            )],
        )
    if len(report.domain_records) > 0:
        layout.append(
            [sg.Text("Match domains:")],
        )
        layout.append(
            [sg.Table(
                values=matchDomains,
                headings=["domain", "type", "value"],
                auto_size_columns=True,  # 自动调整列宽（根据上面第一次的values默认值为准，update时不会调整）
                display_row_numbers=True,  # 序号
                justification='center',
                font=('微软雅黑', 12),
                text_color='black',
                background_color='white',
                enable_events=True,
                bind_return_key=True,
                tooltip='This is a table'
            )]
        )
    return sg.Window("Report", layout, finalize=True)


if __name__ == '__main__':
    sg.theme("Light Green")

    pcapAnalyser = PcapAnalyser()
    window1, window2 = makeWindow1(), None
    inputPcapPath = window1["inputPcapPath"]
    progressBar = window1["analyse-progress"]
    while True:
        window, event, values = sg.read_all_windows()
        if window == window1:
            # main window
            if event == "analyse":
                if window2 is not None:
                    window2.close()
                    window2 = None
                # do analyse
                path = values["inputPcapPath"]
                if not os.path.exists(path):
                    sg.popup_error("File not exists!")
                else:
                    # text = sg.popup_get_file("Please select a pcap file", no_window=True)
                    reportId = pcapAnalyser.dealPcapFile(path, lambda progress: progressBar.update_bar(progress))
                    # 获取数据库session
                    engine = getEngine()
                    DBSession = sessionmaker(bind=engine)
                    session = DBSession()
                    report = session.query(Report).filter(Report.id == reportId).first()
                    window2 = makeReportTableWindow(report)
                    report = None
                    session.close()
            elif event == sg.WIN_CLOSED:
                break
        elif window == window2:
            # table window
            if event == sg.WIN_CLOSED:
                window2.close()
                window2 = None
    window1.close()
    if window2 is not None:
        window2.close()
