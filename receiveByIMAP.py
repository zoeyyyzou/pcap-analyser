import imaplib

from imapclient import IMAPClient



# # 此函数通过使用imaplib实现接收邮件
# def recv_email_by_imap4():
#     # 要进行邮件接收的邮箱。改成自己的邮箱
#     email_server = None
#     email_address = "zoeyyyzou@163.com"
#     # 要进行邮件接收的邮箱的密码。改成自己的邮箱的密码
#     email_password = "RGMQUXRFPXUOLWRD"
#     # 邮箱对应的imap服务器，也可以直接是IP地址
#     # 改成自己邮箱的imap服务器；qq邮箱不需要修改此值
#     imap_server_host = "imap.163.com"
#     # 邮箱对应的pop服务器的监听端口。改成自己邮箱的pop服务器的端口；qq邮箱不需要修改此值
#
#     try:
#         # 连接imap服务器。如果没有使用SSL，将IMAP4_SSL()改成IMAP4()即可其他都不需要做改动
#         email_server = imaplib.IMAP4(host=imap_server_host)
#         print("imap4----connect server success, now will check username")
#     except:
#         print("imap4----sorry the given email server address connect time out")
#         exit(1)
#     try:
#         # 验证邮箱及密码是否正确
#         email_server.login(email_address, email_password)
#         print("imap4----username exist, now will check password")
#     except:
#         print("imap4----sorry the given email address or password seem do not correct")
#         exit(1)
#
#     email_server.id_({"name": "IMAPClient", "version": "2.1.0"})
#
#     # 邮箱中其收到的邮件的数量
#     email_server.select()
#     email_count = len(email_server.search(None, 'ALL')[1][0].split())
#     # 通过fetch(index)读取第index封邮件的内容；这里读取最后一封，也即最新收到的那一封邮件
#     typ, email_content = email_server.fetch(f'{email_count}'.encode(), '(RFC822)')
#     # 将邮件内存由byte转成str
#     email_content = email_content[0][1].decode()
#     print(email_content)
#     # 关闭select
#     email_server.close()
#     # 关闭连接
#     email_server.logout()


if __name__ == '__main__':
    # recv_email_by_imap4()
    server = IMAPClient("imap.163.com", ssl=False, port=143)
    server.login("zoeyyyzou@163.com", "RGMQUXRFPXUOLWRD")

    server.id_({"name": "IMAPClient", "version": "2.1.0"})

    server.select_folder('INBOX')

    # search criteria are passed in a straightforward way
    # (nesting is supported)
    messages = server.search(['NOT', 'DELETED'])

    # fetch selectors are passed as a simple list of strings.
    response = server.fetch(messages, ['RFC822'])

    # `response` is keyed by message id and contains parsed,
    # converted response items.
    for message_id, data in response.items():
        print(data)
        # print('{id}: {size} bytes, flags={flags}'.format(
        #     id=message_id,
        #     size=data[b'RFC822.SIZE'],
        #     flags=data[b'FLAGS']))

    print(messages)
