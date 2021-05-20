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


def dealPcapFile(inputFile: str, progressCallback):
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
    session = DBSession()

    # 将对比的特征生成报告
    report = Report(title=f"{f.name} report", description="",
                    total_domain_num=0,
                    total_packet_num=0,
                    total_flow_num=0)

    extractors = [FlowExtractor("flow.csv"), ICMPExtractor("icmp.csv")]
    dnsExtractor = DNSExtractor()
    startTime = None
    for ts, buf in pcap:
        progressCallback(f.tell() * 100 / totalSize)
        # print(f.tell())
        if not startTime:
            startTime = ts
            report.start_time = datetime.fromtimestamp(startTime)
            report.end_time = report.start_time
        report.total_packet_num += 1
        ethPacket = dpkt.ethernet.Ethernet(buf)
        for extractor in extractors:
            extractor.addPacket(ethPacket, ts)

        # DNS
        res = dnsExtractor.getValue(ethPacket, ts)
        if len(res) > 0:
            # 提取到DNS记录
            dr = DomainRecord(**DNSRecord(res).toDomainRecord())
            report.total_domain_num += 1
            # 检索数据库，如果有想关联的 Observable，就存到report当中，如果没有，则忽略
            observables = session.query(Domain). \
                filter(Domain.value == dr.domain). \
                all()
            if len(observables) > 0:
                dr.observables = observables
                report.domain_records.append(dr)

    for extractor in extractors:
        extractor.done()

    # 填充 FlowRecord
    flowExtractor = extractors[0]
    for key in flowExtractor.flowMap:
        flow = flowExtractor.flowMap[key]
        record = FlowRecord(**flow.toFlowRecord())
        report.total_flow_num += 1
        # 检索数据库，如果有相关联的 Observable，就存到report当中，如果没有，则忽略
        observables = session.query(Address). \
            filter(or_(Address.value == flow.srcIP, Address.value == flow.dstIP)). \
            all()
        # 如果没有相关联的 Observable，则忽略掉
        if len(observables) <= 0:
            continue

        record.observables = observables
        report.flow_records.append(record)
        # if flow.lastTime > report.end_time:
        #     report.end_time = flow.lastTime
    session.add(report)
    session.commit()

    # output report
    outputStr = f"Report title: {report.title}"
    outputStr += f"\ntotal_packet_num: {report.total_packet_num}"
    outputStr += f"\ntotal_flow_num: {report.total_flow_num} / match_flow_num: {len(report.flow_records)}"
    outputStr += f"\ntotal_domain_num: {report.total_domain_num} / match_domain_num: {len(report.domain_records)}"
    session.close()
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

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Cancel':  # if user closes window or clicks cancel
            break
        elif event == "analyse":
            path = values["inputPcapPath"]
            # text = sg.popup_get_file("Please select a pcap file", no_window=True)
            res = dealPcapFile(path, lambda progress: progressBar.update_bar(progress))
            sg.popup_ok(res)

    window.close()
