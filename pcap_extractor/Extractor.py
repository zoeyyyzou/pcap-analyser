from abc import ABCMeta, abstractmethod
from dpkt import ethernet


class Extractor(object):
    """
    提取器的基类，定义了所有提取器通用的功能
    """
    __metaclass__ = ABCMeta  # 指定这是一个抽象类

    def __init__(self, valueCallback):
        self.valueCallback = valueCallback

    @abstractmethod
    def addPacket(self, ethPacket: ethernet.Ethernet, timestamp: float):
        pass

    @abstractmethod
    def done(self):
        pass
