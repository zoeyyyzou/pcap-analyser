from io import BytesIO
from contextlib import closing


class POP3Parser:
    def parse(self, commandBytes: bytes, responseBytes: bytes):
        """
        解析 TCP 流向，从其中解析出邮件
        :param commandBytes:    传入POP3命令，目的端口为110
        :param responseBytes:   传入POP3响应，源端口为110
        :return:
        """
        commands = []
        with closing(BytesIO(commandBytes)) as data:
            for line in data.readlines():
                commands.append(line.strip().upper())
        response = []
        # +OK
        with closing(BytesIO(responseBytes)) as data:
            tmp = None
            for line in data.readlines():
                if line.startswith(b'+OK') or line.startswith(b'-ERR'):
                    if tmp is not None:
                        response.append(tmp)
                    tmp = line
                else:
                    tmp += line
        response.append(line)
        print(commands, len(commands), len(response))
