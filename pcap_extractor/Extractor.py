from abc import ABCMeta, abstractmethod
from dpkt import ethernet


class Extractor(object):
    __metaclass__ = ABCMeta  # 指定这是一个抽象类

    def __init__(self, valueCallback):
        self.valueCallback = valueCallback

    @abstractmethod
    def addPacket(self, ethPacket: ethernet.Ethernet, timestamp: int):
        pass


    @abstractmethod
    def done(self):
        pass
