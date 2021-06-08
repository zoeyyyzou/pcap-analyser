#!/usr/bin/env python
# coding=utf-8
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from email.utils import parseaddr, formataddr

# 邮件对象:
msg = MIMEMultipart()
msg['From'] = "zoeyyyzou@163.com"
msg['To'] = "zoeyyyzou@163.com"
msg['Subject'] = "Welcome"

# 邮件正文是MIMEText:
msg.attach(MIMEText('test send with file...', 'plain', 'utf-8'))
msg.attach(MIMEText("<html><body><h1>test send with file...</h1></body></html>", 'html', 'utf-8'))

# 添加附件就是加上一个MIMEBase，从本地读取一个图片:
with open('guelph.png', 'rb') as f:
    # 设置附件的MIME和文件名，这里是png类型:
    mime = MIMEBase('image', 'png', filename='test.png')
    # 加上必要的头信息:
    mime.add_header('Content-Disposition', 'attachment', filename='test.png')
    mime.add_header('Content-ID', '<0>')
    mime.add_header('X-Attachment-Id', '0')
    # 把附件的内容读进来:
    mime.set_payload(f.read())
    # 用Base64编码:
    encode_base64(mime)
    # 添加到MIMEMultipart:
    msg.attach(mime)

server = smtplib.SMTP("smtp.163.com", 25)
server.set_debuglevel(1)
server.login("zoeyyyzou@163.com", "RGMQUXRFPXUOLWRD")
server.sendmail("zoeyyyzou@163.com", ["yzou10@uoguelph.ca"], msg.as_string())
server.quit()
