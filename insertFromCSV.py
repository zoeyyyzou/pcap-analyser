from sqlalchemy import create_engine, text, or_
from sqlalchemy.orm import sessionmaker
from entity.cctx import Address, Domain, Initial, Report, DomainRecord, FlowRecord, FileHashRecord
from sqlalchemy.exc import IntegrityError

import csv


def getEngine():
    engine = create_engine("sqlite+pysqlite:///cctx.db", echo=False, future=True)

    # # sqlite3 开启外键约束
    # with engine.connect() as conn:
    #     conn.execute(text("pragma foreign_keys=on"))

    Initial(engine)

    return engine


def insertToDatabaseFromFile():
    engine = getEngine()
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    # domain
    file = open("domain.csv")
    csvFile = csv.reader(file)
    titles = csvFile.__next__()
    for item in csvFile:
        domain = Domain.build(titles, item)
        res = session.query(Domain).filter(Domain.stix_id == item[0]).all()
        if len(res) > 0:
            continue
        session.add(domain)
        session.commit()

    # address
    file = open("address.csv")
    csvFile = csv.reader(file)
    titles = csvFile.__next__()
    for item in csvFile:
        address = Address.build(titles, item)
        res = session.query(Address).filter(Address.stix_id == item[0]).all()
        if len(res) > 0:
            return
        session.add(address)
        try:
            session.commit()
        except IntegrityError:
            pass
    session.close()


if __name__ == '__main__':
    insertToDatabaseFromFile()
