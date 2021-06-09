import re

from pcap_extractor.mail import Mail
from io import BytesIO
from contextlib import closing
from email.parser import Parser


class IMAPParser:
    """
    RFC: https://datatracker.ietf.org/doc/html/rfc3501
    """
    def parse(self, commandBytes: bytes, responseBytes: bytes) -> [Mail]:
        """
        解析 IMAP TCP流，从其中解析出邮件
        :param commandBytes:
        :param responseBytes:
        :return:
        """
        emails = []
        with closing(BytesIO(commandBytes)) as data:
            commands = data.readlines()
        if len(commands) < 0:
            return []
        commandIndex = 0
        start = 0
        responses = []
        currentCommandId, isFetch = commands[commandIndex][:5], commands[commandIndex][6:].upper().startswith(b"FETCH")
        with closing(BytesIO(responseBytes)) as data:
            lines = data.readlines()
        for idx, line in enumerate(lines):
            if line.startswith(currentCommandId):
                if isFetch:
                    responses.append(b''.join(lines[start:idx]))
                start = idx + 1
                commandIndex += 1
                if commandIndex < len(commands):
                    currentCommandId, isFetch = commands[commandIndex][:5], commands[commandIndex][
                                                                            6:].upper().startswith(b"FETCH") or \
                                                commands[commandIndex][6:].upper().startswith(b"UID FETCH")
                else:
                    break

        for response in responses:
            # 在这里处理 fetch 的结果
            with closing(BytesIO(response)) as data:
                result = re.search(rb'\* [0-9]+ FETCH(.*?){(.*?)}\r\n', data.readline())
                while result is not None:
                    size = int(result.group(2))
                    tmp = data.read(size)
                    # 忽略掉结束标识
                    data.read(3)
                    mail = Mail()
                    msg = Parser().parsestr(tmp.decode('utf-8'))
                    if msg.get("From") is not None and msg.get("To") is not None:
                        mail.parse(msg)
                        emails.append(mail)
                    result = re.search(rb'\* [0-9]+ FETCH(.*?){(.*?)}\r\n', data.readline())
        # print(responses[7], len(responses[7]))
        return emails
