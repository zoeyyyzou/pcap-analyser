class Mail:
    def __init__(self):
        self.data = ""  # 消息内容
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
        # self.MessageID = ""  # 消息ID
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
        return f"Mail(Subject={self.Subject}, From={self.From}, To={self.To}, Cc={self.Cc}, Data={self.data})"
