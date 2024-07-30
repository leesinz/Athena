<h4 align="center">Athena旨在从多个漏洞源和厂商通告中聚合漏洞信息，并实现实时推送以增强安全监控和响应能力</h4>
<p align="center">
    <a href="https://www.python.org/downloads/release/python-387/">
        <img src="https://img.shields.io/badge/python-3.8.7-blue.svg">
    </a>
	<a href="https://github.com/leesinz/Athena/stargazers">
        <img src="https://img.shields.io/github/stars/leesinz/Athena?style=social">
    </a>
    <a href="https://github.com/leesinz/Athena/watchers">
        <img src="https://img.shields.io/github/watchers/leesinz/Athena?style=social">
    </a>
    <a href="https://github.com/leesinz/Athena/network/members">
        <img src="https://img.shields.io/github/forks/leesinz/Athena?style=social">
    </a>

![image-20240730151807137](readme/image-20240730151807137.png)

## WHAT

在古希腊神话中，雅典娜（**Athena**）是智慧与战争的女神，守护着人类的知识与安全。受此启发，此项目 **Athena** 旨在守护现代网络世界的安全。

**Athena** 是一个用于监控各个漏洞源和安全厂商的漏洞通告，并进行实时推送的Python项目，希望帮助安全团队及时获取高风险漏洞信息，提供快速响应能力。

**Athena**会聚合所有漏洞源漏洞信息，存入数据库，并筛选出高危漏洞进行实时推送，推送渠道支持钉钉机器人、企微机器人等等。

### 已覆盖漏洞源

- [x] afrog
- [x] exploit-db
- [x] github
- [x] metasploit
- [x] packetstormsecurity
- [x] POC
- [x] seebug
- [x] vulhub
- [x] 微步漏洞情报
- [x] 阿里云高危漏洞库
- [x] OSCS漏洞情报库
- [x] 奇安信漏洞通告


### TODO

- [ ] 每日所有漏洞信息邮件推送（模板doing，V2.0实现）
- [ ] flask+datatables+echarts实现完整前后端（V2.0实现）


## WHY

目前已有不少用于漏洞监控的优秀开源项目，但是存在监控源较少、对数据的处理粒度较大、可视化效果较差等问题，导致漏洞数据从收集、聚合、展示到推送的整个过程略显繁琐，**Athena**希望能够解决这些问题，用最简单的配置即可实现最全面的功能。

## HOW

### 环境

**python 3.8+**

```bash
sudo apt-get update
sudo apt-get install python3.8 python3.8-venv python3.8-dev
```

**mysql**

```bash
sudo apt-get update
sudo apt-get install mysql-server
sudo mysql_secure_installation
```

设置密码并创建数据库，将配置信息同步到config.yaml。

如果遇到

`Error connecting mysql database:%!(EXTRA *mysql.MySQLError=Error 1698 (28000): Access denied for user 'root'@'localhost', string=)`

重置密码即可：

`ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'newpasswd';`

### 安装

```
git clone xxx
pip install -r requirements.txt
```

### 配置

config.yaml

```yaml
github:
  token: ""

#collectors默认为空，表示爬取所有漏洞源信息，如需指定特定源，可修改此项.可选项为['POC','Afrog','PacketStorm','Github','Seebug','OSCS','Ali','QAX','ThreatBook','Vulhub','MSF','ExploitDB']
collectors: []

mysql:
  host: 127.0.0.1
  port: 3306
  database: ""
  username: ""
  password: ""

#通知选项，如需开启，则将enable置为true，并配置相关token。不建议使用邮件，邮件模板预计在V2.0完成
notify:
  #https://developer.work.weixin.qq.com/document/path/91770
  wxwork:
    enable: true
    key: 
    
  #https://open.dingtalk.com/document/robots/custom-robot-access
  dingtalk:
    enable: false
    access_token: 
    secret: 

  email:
    enable: false
    smtp_server:
    smtp_port:
    username:
    password:
    from:
    to:
      -
      -

```

### 运行逻辑

![draw](readme/draw.png)

### 快速开始

seebug监控默认关闭，由于使用的是chrome.driver无头浏览器的方式，可能产生内存问题，最终导致程序中断，如果需要，去掉collectors/manager.py中self.collector_classes的注释即可：

```python
self.collector_classes = {
    'ExploitDB': ExploitDBCollector,
    'MSF': MSFCollector,
    'Vulhub': VulhubCollector,
    'POC': POCCollector,
    'Afrog': AfrogCollector,
    'PacketStorm': PacketStormCollector,
    # chrome.driver starts frequently, which may cause memory issues and eventually lead to code termination
    # 'Seebug': SeebugCollector,
    'Github': GitHubCollector,
    'OSCS': OSCSCollector,
    'Ali': AliCollector,
    'QAX': QAXCollector,
    'ThreatBook': ThreatBookCollector
        }
```

默认10分钟运行一次，如需更改，修改main.py即可：

```python
while True:
    vulnerabilities = gather_data()
    filter_high_risk_vuls(vulnerabilities)
    time.sleep(600)
```

安装完需要的库，配置好config.yaml后，即可开始运行。

![image-20240730174829661](readme/image-20240730174829661.png)

推送内容如下：

![image-20240730174957206](readme/image-20240730174957206.png)

### 扩展

如需扩展其他漏洞源数据，实现base_collector.py中的VulnerabilityCollector类即可，漏洞信息的字段如下：

```
vulnerability = {
                        'name': name,
                        'cve': cve,
                        'severity': severity,
                        'description': description,
                        'source': self.source_name,
                        'date': date,
                        'link': link
                    }
```

如某个字段内容为空，置空即可，在推送时会自动过滤。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=leesinz/Athena&type=Date)](https://star-history.com/#leesinz/Athena&Date)