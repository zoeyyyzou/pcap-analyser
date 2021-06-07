from io import BytesIO
from contextlib import closing
from pcap_extractor.mail import Mail


class SMTPParser:
    """
    SMTP 解析器，参考：https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1
    EHLO => 向SMTP服务器提交本地客户端信息，用来获取 SMTP 邮件服务器的一些描述信息， eg.: ehlo Zoey.local
    HELO => 向SMTP服务器提交本地客户端信息，用来获取 SMTP 邮件服务器的一些描述信息， eg.: ehlo Zoey.local
    MAIL => 启动一个邮件事务（包含发件人的地址），eg.: mail FROM:<123zoeyyy@163.com>
    RCPT => 用这个命令标识单个邮件收件人，eg.: rcpt TO:<yzou10@uoguelph.ca>
    DATA => 标识邮件数据的起始，eg.: data
    RSET => 忽略
    VRFY => 忽略
    AUTH => 发送验证信息，忽略
    EXPN => 忽略
    HELP => client向server请求帮助信息，忽略
    NOOP => 忽略
    QUIT => 结束传输通道
    """

    def __init__(self):
        self.commandMap = {
            b"EHLO": self.dealEHLO,
            b"HELO": self.dealHELO,
            b"MAIL": self.dealMAIL,
            b"RCPT": self.dealRCPT,
            b"DATA": self.dealDATA,
            b"RSET": self.ignore,
            b"VRFY": self.ignore,
            b"AUTH": self.ignore,
            b"EXPN": self.ignore,
            b"HELP": self.ignore,
            b"NOOP": self.ignore,
            b"QUIT": self.dealQUIT
        }

    def dealEHLO(self, mail: Mail, msg: bytes):
        pass

    def dealHELO(self, mail: Mail, msg: bytes):
        pass

    def dealMAIL(self, mail: Mail, msg: bytes):
        pass

    def dealRCPT(self, mail: Mail, msg: bytes):
        pass

    def dealDATA(self, mail: Mail, msg: bytes):
        pass

    def dealQUIT(self, mail: Mail, msg: bytes):
        """
        包头：https://help.aliyun.com/document_detail/51584.html
        :param mail:
        :param msg:
        :return:
        """
        if msg.endswith(b"\r\n.\r\n"):
            msg = msg[:len(msg) - 5]
        with closing(BytesIO(msg)) as data:
            line = data.readline()
            while line not in [b'', b'\r\n']:
                keyVal = line.split(b':')
                if len(keyVal) < 2:
                    line = data.readline()
                    continue
                val = b':'.join(keyVal[1:]).strip()
                if keyVal[0] == b"From":
                    mail.From = val
                elif keyVal[0] == b"To":
                    mail.To = val
                elif keyVal[0] == b"Cc":
                    mail.Cc = val
                elif keyVal[0] == b"Subject":
                    mail.Subject = val
                elif keyVal[0] == b"Content-Type":
                    mail.ContentType = val
                elif keyVal[0] == b"Content-Transfer-Encoding":
                    mail.ContentTransferEncoding = val
                elif keyVal[0] == b"Date":
                    mail.Date = val
                line = data.readline()
            mail.data = b"".join(data.readlines())

    def ignore(self, mail: Mail, msg: bytes):
        pass

    def parse(self, data: bytes) -> [Mail]:
        """
        传入单向的 TCP 流，client => server
        :param data:
        :return:
        """

        mails = []
        with closing(BytesIO(data)) as data:
            line = data.readline()
            msg = bytes()
            mail = Mail()
            while line not in [b'']:
                if len(line) < 4:
                    msg += line
                    line = data.readline()
                    continue
                command = line[:4].upper()
                if command in self.commandMap:
                    if command == b"RCPT":
                        mail = Mail()
                        mails.append(mail)
                    if command == b"DATA":
                        msg = bytes()
                    self.commandMap[command](mail, msg)

                    msg = bytes()
                else:
                    msg += line

                line = data.readline()
        return mails
