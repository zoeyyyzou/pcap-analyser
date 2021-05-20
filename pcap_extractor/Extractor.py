from abc import ABCMeta, abstractmethod
from dpkt import ethernet


class Extractor(object):
    __metaclass__ = ABCMeta  # 指定这是一个抽象类

    @abstractmethod
    def addPacket(self, ethPacket: ethernet.Ethernet, timestamp: int):
        pass

    @abstractmethod
    def done(self):
        pass

    @abstractmethod
    def getTitle(self):
        pass

    @abstractmethod
    def getValue(self, ethPacket: ethernet.Ethernet, timestamp: int):
        pass
