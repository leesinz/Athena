import datetime
import requests
from bs4 import BeautifulSoup
from .base_collector import VulnerabilityCollector
from .decorators import retry


class AliCollector(VulnerabilityCollector):
    def __init__(self):
        ali_url = "https://avd.aliyun.com/high-risk/list?page=1"
        super().__init__('Aliyun', ali_url)

    @retry()
    def fetch_data(self):
        response = requests.get(self.source_url)
        response.raise_for_status()
        return response.text

    @staticmethod
    @retry()
    def extract_info(link):
        res = requests.get(link)
        res.raise_for_status()

        soup = BeautifulSoup(res.content, 'html.parser')
        cve_element = soup.find('div', class_='metric-value')
        cve = cve_element.text.strip() if cve_element else ''

        description_header = soup.find('h6', string='漏洞描述')
        description_div = description_header.find_next('div') if description_header else None
        if description_div:
            description_lines = description_div.stripped_strings  # 逐行提取并去除多余的空白字符
            description = ' '.join(description_lines)
        else:
            description = ''

        return cve.replace("N/A",""), description

    def parse_data(self, raw_data):
        today = datetime.date.today().strftime("%Y-%m-%d")
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        vulnerabilities = []
        soup = BeautifulSoup(raw_data, "html.parser")
        trs = soup.find_all('tr')
        for tr in trs:
            tds = tr.find_all('td')
            if tds:
                a_tag = tds[0].find('a')
                name = tds[1].get_text().strip()
                disclosure = tds[3].get_text().strip()
                if disclosure != today and disclosure != yesterday:
                    continue
                vulnerability_link = a_tag['href']
                link = "https://avd.aliyun.com" + vulnerability_link
                cve, description = self.extract_info(link)
                vulnerability = {
                    "name": name,
                    'cve': cve,
                    'severity': 'high',
                    'description': description,
                    "source": self.source_name,
                    "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "link": link
                }
                vulnerabilities.append(vulnerability)
        return vulnerabilities
