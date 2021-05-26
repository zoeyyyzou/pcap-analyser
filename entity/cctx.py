from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, Float, Enum, Table
from datetime import datetime

Base = declarative_base()


###############################################################################################
# CCTX Observables
###############################################################################################

class Address(Base):
    """
    地址表，用来存储 ipv4, ipv6
    """
    __tablename__ = "address"

    id = Column(Integer, primary_key=True)  # 主键
    stix_id = Column(String, default="", nullable=False, unique=True)  # CCIX 获取到的 STIX observable object id
    type = Column(Enum("ipv4-addr", "ipv6-addr"), server_default="ipv4-addr", nullable=False)  # 地址类型
    value = Column(String, default="", nullable=False)  # 地址

    created_at = Column(DateTime, default=datetime.now)  # 创建时间
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)  # 更新时间

    @staticmethod
    def build(titles: [], values: []):
        mMap = {}
        for i in range(len(titles)):
            mMap[titles[i]] = values[i]
        address = Address(
            stix_id=mMap["id"],
            type=mMap["category"],
            value=mMap["value"]
        )
        return address


class Domain(Base):
    """
    域名表，用来存储域名
    """
    __tablename__ = "domain"

    id = Column(Integer, primary_key=True)  # 主键
    stix_id = Column(String, default="", nullable=False, unique=True)  # CCIX 获取到的 STIX observable object id
    value = Column(String, default="", nullable=False)  # 域名

    created_at = Column(DateTime, default=datetime.now)  # 创建时间
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)  # 更新时间

    @staticmethod
    def build(titles: [], values: []):
        mMap = {}
        for i in range(len(titles)):
            mMap[titles[i]] = values[i]
        domain = Domain(
            stix_id=mMap["id"],
            value=mMap["value"]
        )
        return domain


#######################################################################################
# Report
#######################################################################################

class Report(Base):
    """
    报告类：每提交一个 pcap 文件并解析对比，这个pcap文件的对比结果会关联到一个报告
    """
    __tablename__ = "report"

    id = Column(Integer, primary_key=True)  # 主键
    title = Column(String, default="")  # 报告 Title
    description = Column(String, default="")  # 报告描述
    total_packet_num = Column(Integer, default=0)  # 总的数据包的数量
    total_flow_num = Column(Integer, default=0)  # 总的网络流的数量 TCP / UDP 流
    total_domain_num = Column(Integer, default=0)  # 总的解析到的域名数量
    start_time = Column(DateTime, nullable=False)  # 网络流量起始时间
    end_time = Column(DateTime)  # 网络流量截止时间
    flow_records = relationship("FlowRecord")
    domain_records = relationship("DomainRecord")

    created_at = Column(DateTime, default=datetime.now)  # 创建时间
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)  # 更新时间


# FlowRecord 和 Address 表的外键关联
flow_record_address = Table(
    "flow_record_address", Base.metadata,
    Column("address_id", Integer, ForeignKey("address.id")),
    Column("flow_record_id", Integer, ForeignKey("flow_record.id", ondelete="CASCADE")),
)


class FlowRecord(Base):
    """
    Flow 记录类：从 pcap 文件中提取出的 TCP/UDP 流，并且其源IP地址或者目的IP地址存在于 CCTX 的 Observable 当中
    """

    __tablename__ = "flow_record"

    id = Column(Integer, primary_key=True)  # 主键
    src_ip = Column(String, nullable=False)  # 源 IP 地址
    dst_ip = Column(String, nullable=False)  # 目的 IP 地址
    src_port = Column(Integer, nullable=False)  # 源端口
    dst_port = Column(Integer, nullable=False)  # 目的端口
    type = Column(Enum("ipv4-addr", "ipv6-addr"), server_default="ipv4-addr", nullable=False)  # 地址类型
    protocol = Column(Enum("tcp", "udp"), server_default="tcp", nullable=False)  # 协议类型
    start_time = Column(DateTime, nullable=False)  # 网络流量的起始时间
    end_time = Column(DateTime, nullable=False)  # 网络流量终止时间
    src_packets = Column(Integer, default=0)  # 源发往目的的包的数量
    src_byte_count = Column(Integer, default=0)  # 源发往目的的有效负载的字节数
    dst_packets = Column(Integer, default=0)  # 目的发往源的网络包的数量
    dst_byte_count = Column(Integer, default=0)  # 目的发往源的有效负载的字节数

    # 关联
    observables = relationship("Address", secondary=flow_record_address)  # 关联的 CCTX Observables（一对多）
    report_id = Column(Integer, ForeignKey("report.id"))

    def __repr__(self):
        return f'FlowRecord(src_ip={self.src_ip}, dst_ip={self.dst_ip}, src_port={self.src_port}, ' \
               f'dst_port={self.dst_port}, type={self.type}, protocol={self.protocol},' \
               f'src_packets={self.src_packets}, dst_packets={self.dst_packets})'


# DomainRecord 和 Domain 表的外键关联
domain_record_domain = Table(
    "domain_record_domain", Base.metadata,
    Column("domain_id", Integer, ForeignKey("domain.id")),
    Column("domain_record_id", Integer, ForeignKey("domain_record.id", ondelete="CASCADE"))
)


class DomainRecord(Base):
    """
    Domain 记录类：从 pcap 文件中提取出的域名，且该域名存在于 CCTX 的 Observable 当中
    """

    __tablename__ = "domain_record"
    id = Column(Integer, primary_key=True)  # 主键
    domain = Column(String, nullable=False)  # 域名
    domain_type = Column(String, default="A")  # 记录类型
    value = Column(String, nullable=False)  # 域名解析值
    timestamp = Column(DateTime, nullable=False)  # response 的时间戳

    # 关联
    observables = relationship("Domain", secondary=domain_record_domain)
    report_id = Column(Integer, ForeignKey("report.id"), nullable=False)

    def __repr__(self):
        return f"DomainRecord(domain={self.domain}, type={self.domain_type}, value={self.value})"


def Initial(engine):
    """
    传入 sqlalchemy 数据库引擎，初始化数据库表
    1. 如果数据库表不存在，则创建；
    2. 如果数据库表已经存在，则什么都不做
    :param engine:
    :return:
    """
    Base.metadata.create_all(engine)
