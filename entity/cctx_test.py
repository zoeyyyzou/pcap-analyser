import unittest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from entity.cctx import Address, Domain, Initial, Report, DomainRecord
from datetime import datetime


def getEngine():
    engine = create_engine("sqlite+pysqlite:///cctx.db", echo=False, future=True)

    # sqlite3 开启外键约束
    with engine.connect() as conn:
        conn.execute(text("pragma foreign_keys=on"))

    Initial(engine)

    return engine


class TestCCTX(unittest.TestCase):
    def setUp(self) -> None:
        engine = getEngine()
        DBSession = sessionmaker(bind=engine)
        self.session = DBSession()

    def tearDown(self) -> None:
        self.session.close()

    def test_domain_record(self):
        data = {
            "domain": "albemalb.com",
            "domain_type": "A",
            "value": "54.227.98.220",
            "timestamp": datetime.now()
        }

        # first query domain table
        res = self.session.query(Domain).filter(Domain.value == data["domain"]).all()
        self.assertEqual(len(res), 1)

        domain = res[0]

        # create DomainRecord
        dr = DomainRecord(**data)
        dr.observables.append(domain)

        self.session.add(dr)
        self.session.commit()

        # delete dr
        self.session.delete(dr)
        self.session.commit()
        pass

    def test_report(self):
        data = {
            "title": "report title",
            "description": "report description",
            "total_packet_num": 0,
            "start_time": datetime.now(),
            "end_time": datetime.now(),
        }
        report = Report(**data)

        # add
        self.session.add(report)
        self.session.commit()

        # Query
        res = self.session.query(Report).filter(Report.id == report.id).all()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].title, data["title"])

        # delete
        self.session.delete(report)
        self.session.commit()
