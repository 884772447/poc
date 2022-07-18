import socket
import struct


def recv_data(sock, buf_size=1024):
    """解决粘包"""
    # 先接受命令执行结果的长度
    x = sock.recv(4)
    all_size = struct.unpack('i', x)[0]
    # 接收真实数据
    recv_size = 0
    data = b''
    while recv_size < all_size:
        data += sock.recv(buf_size)
        recv_size += buf_size
    return data


def send_data(conn, cmd):
    """发送数据也解决粘包问题"""
    if type(cmd) == str:
        cmd = cmd.encode("utf-8")
        # 新增发送命令的粘包解决方案
        # 计算命令长度 , 打包发送
        cmd_len = struct.pack('i', len(cmd))
        # 先发送长度
        conn.send(cmd_len)
        # 再发送命令
        conn.send(cmd)


def main():
    # 监听
    server = socket.socket()
    server.bind(('192.168.6.147', 9090))
    server.listen(2)
    # 等待连接 , conn是一个通信管道,addr是链接过来的客户端的地址
    print('等待连接中......')
    conn, c_addr = server.accept()
    while 1:
        try:
            cmd = input(f'{c_addr}>').strip()
            if not cmd:
                continue
            if cmd == "quit":
                send_data(conn, cmd)
                break
            send_data(conn, cmd)
            # 接收客户端传来的内容
            data = recv_data(conn)
            print(data.decode("gbk").strip())
        except Exception as e:
            print(e)
    conn.close()
    server.close()


if __name__ == '__main__':
    main()
