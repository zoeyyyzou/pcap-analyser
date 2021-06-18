import base64
import hashlib
import json
from email.parser import Parser
from email.header import decode_header
from email.message import Message
from email.utils import parseaddr


class MailFile:
    def __init__(self, fileName, fileType, fileData):
        self.fileName = fileName
        self.fileType = fileType
        self.fileData = fileData


def guess_charset(msg):
    charset = msg.get_charset()
    if charset is None:
        content_type = msg.get('Content-Type', '').lower()
        pos = content_type.find('charset=')
        if pos >= 0:
            charset = content_type[pos + 8:].strip()
    return charset


def decode_str(s):
    value, charset = decode_header(s)[0]
    if charset:
        value = value.decode(charset)
    return value


class Mail:
    def __init__(self):
        self.plain = ""  # 消息内容
        self.html = ""  # html格式的内容
        self.files = []
        # self.Received = ""  # 传输路径
        # self.ReturnPath = ""  # 回复地址
        # self.DeliveredTo = ""  # 发送地址
        # self.ReplyTo = ""  # 回复地址
        self.From = ""  # 发件人地址
        self.To = ""  # 收件人地址
        self.Cc = ""  # 抄送地址
        # self.Bcc = ""  # 暗送地址
        self.Date = ""  # 日期和时间
        self.Subject = ""  # 主题
        self.MessageID = ""  # 消息ID
        # self.MIMEVersion = ""  # MIME 版本
        """
        内容类型（Content-Type），表现形式为：Content-Type: [type]/[subtype]。
            其中 type 的形式为：
            text：用于标准化地表示的文本信息，文本消息可以是多种字符集和或者多种格式的。
            Image：用于传输静态图片数据。
            Audio：用于传输音频或者音声数据。
            Video：用于传输动态影像数据，可以是与音频编辑在一起的视频数据格式。
            Application：用于传输应用程序数据或者二进制数据。
            Message：用于包装一个 E-mail 消息。
            Multipart：用于连接消息体的多个部分构成一个消息，这些部分可以是不同类型的数据。
            其中 subtype 用于指定 type 的详细形式，常用的 subtype 如下所示：
            text/plain（纯文本）
            text/html（HTML 文档）
            application/xhtml+xml（XHTML 文档）
            image/gif（GIF 图像）
            image/jpeg（JPEG 图像）
            image/png（PNG 图像）
            video/mpeg（MPEG 动画）
            application/octet-stream（任意的二进制数据）
            message/rfc822（RFC 822 形式）
            multipart/alternative（HTML 邮件的 HTML 形式和纯文本形式，相同内容使用不同形式表示。）
        """
        self.ContentType = ""  # 内容的类型
        """
        内容传输编码（Content-Transfer-Encoding），指定内容区域使用的字符编码方式。
        通常为：7bit，8bit，binary，quoted-printable，base64。
        """
        self.ContentTransferEncoding = ""  # 内容的传输编码方式

    def __repr__(self):
        fileHash = b""
        if len(self.files) > 0:
            fileHashes = []
            for item in self.files:
                fileHashes.append(hashlib.md5(item.fileData).hexdigest())
            fileHash = ", ".join(fileHashes)
        if isinstance(self.html, bytes):
            self.html = self.html.decode("utf-8")
        if isinstance(fileHash, bytes):
            fileHash = fileHash.decode("utf-8")
        return json.dumps({
            "Subject": self.Subject,
            "From": self.From,
            "To": self.To,
            "Cc": self.Cc,
            "plain": self.plain,
            "html": self.html,
            "files": fileHash,
            "MessageId": self.MessageID
        }, ensure_ascii=False)
        # return f"Mail(Subject={self.Subject}, From={self.From}, To={self.To}, Cc={self.Cc}, plain={self.plain}, " \
        #        f"html={self.html}, files={fileHash}, MessageId={self.MessageID}"

    def _parse(self, msg: Message, indent):
        """
        https://www.liaoxuefeng.com/wiki/897692888725344/967961517614816
        :param msg:
        :param indent:
        :return:
        """
        if indent == 0:
            for header in ['Subject', 'From', 'To', 'Cc', 'Content-Type', 'Content-Transfer-Encoding', 'Date',
                           'Message-ID']:
                value = msg.get(header, '')
                if value:
                    if header == 'Subject':
                        value = decode_str(value)
                    else:
                        hdr, addr = parseaddr(value)
                        name = decode_str(hdr)
                        value = u'%s <%s>' % (name, addr)
                    if header == 'Content-Type':
                        self.ContentType = value
                    elif header == 'Content-Transfer-Encoding':
                        self.ContentTransferEncoding = value
                    elif header == 'Message-ID':
                        self.MessageID = value
                    else:
                        setattr(self, header, value)
        if msg.is_multipart():
            parts = msg.get_payload()
            for part in parts:
                self._parse(part, indent + 1)
        else:
            content_type = msg.get_content_type()
            if content_type == 'text/plain' or content_type == 'text/html':
                content = msg.get_payload(decode=True)
                charset = guess_charset(msg)
                if charset:
                    content = content.decode(charset)
                if content_type == 'text/plain':
                    self.plain = content
                else:
                    self.html = content
            else:
                fileName = msg.get_filename()
                encoding = msg.get('Content-Transfer-Encoding', '')
                data = bytes(msg.get_payload(), 'utf-8')
                if encoding == 'base64':
                    data = base64.b64decode(data)
                self.files.append(MailFile(fileName, content_type, data))

    def parse(self, msg):
        self._parse(msg, 0)
