from pcapfex.core.Plugins.PluginManager import PluginManager
from pcap_extractor.FileObject import FileObject
from pcap_extractor.FlowBase import FlowBase


class FileScanner:
    def __init__(self, entropy=False):
        self.pm = PluginManager()
        self.useEntropy = entropy

    def findFile(self, stream: FlowBase):
        (stream, result) = self._findFiles(stream)
        return result

    def _findFiles(self, stream: FlowBase):
        files = []
        payloads = []
        streamData = stream.getAllBytes()
        streamPorts = (stream.srcPort, stream.dstPort)

        for protocol in self.pm.getProtocolsByHeuristics(streamPorts):
            payloads = self.pm.protocolDissectors[protocol].parseData(streamData)

            if payloads is not None:
                stream.protocol = self.pm.protocolDissectors[protocol].protocolName
                break

        for encPayload in payloads:
            for decoder in self.pm.decoders:
                payload = self.pm.decoders[decoder].decodeData(encPayload)
                if payload is None:
                    continue

                for dataRecognizer in self.pm.dataRecognizers:
                    for occ in self.pm.dataRecognizers[dataRecognizer].findAllOccurences(payload):
                        file = FileObject(payload[occ[0]:occ[1]], stream)
                        file.fileEncoding = self.pm.dataRecognizers[dataRecognizer].fileEnding
                        file.fileType = self.pm.dataRecognizers[dataRecognizer].dataCategory
                        files.append(file)

                if self.useEntropy:
                    file = FileObject(payload, stream)
                    file.fileType = self.pm.entropyClassifier.classify(payload)
                    files.append(file)

        return stream, files
