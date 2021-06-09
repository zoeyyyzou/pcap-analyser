from io import BytesIO
from contextlib import closing
from pcap_extractor.mail import Mail
from email.parser import Parser


class POP3Parser:
    """
    RFC: https://datatracker.ietf.org/doc/html/rfc1939

    USER [username] 处理用户名
    PASS [password] 处理用户密码
    APOP [Name,Digest] 认可Digest是MD5消息摘要
    STAT 处理请求服务器发回关于邮箱的统计资料，如邮件总数和总字节数
    UIDL [邮件id] 处理返回邮件的唯一标识符，POP3会话的每个标识符都将是唯一的
    LIST [邮件id] 处理返回邮件数量和每个邮件的大小
    RETR [邮件id] 处理返回由参数标识的邮件的全部文本
    DELE [邮件id] 处理服务器将由参数标识的邮件标记为删除，最后由【quit】命令执行
    RSET 处理服务器将重置所有标记为删除的邮件，用于撤消DELE命令
    TOP [邮件id n] 处理服务器将返回由参数标识的邮件前n行内容，n必须是正整数
    NOOP 处理服务器返回一个肯定的响应
    QUIT 终止会话
    """

    def _parseEmail(self, content: bytes) -> Mail:
        pass

    def parse(self, responseBytes: bytes) -> [Mail]:
        """
        解析 TCP 流，从其中解析出邮件
        :param responseBytes:   传入POP3响应，源端口为110
        :return:
        """
        emails = []
        response = []
        # +OK
        lines = []
        with closing(BytesIO(responseBytes)) as data:
            lines = data.readlines()
        start = -1
        for idx, line in enumerate(lines):
            if line.startswith(b'+OK') or line.startswith(b'-ERR'):
                if idx >= 0:
                    tmp = b''.join(lines[start:idx])
                    tmpIdx = tmp.find(b'\r\n')
                    if tmpIdx != -1:
                        tmp = tmp[tmpIdx + 2:]
                    mail = Mail()
                    msg = Parser().parsestr(tmp.decode('utf-8'))
                    if msg.get("From") is not None and msg.get("To") is not None:
                        mail.parse(msg)
                        emails.append(mail)
                    response.append(tmp)
                start = idx
        return emails
