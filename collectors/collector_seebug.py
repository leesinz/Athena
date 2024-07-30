import datetime
import random
import time
from bs4 import BeautifulSoup
from .base_collector import VulnerabilityCollector
from .decorators import retry
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service as ChromeService


class SeebugCollector(VulnerabilityCollector):
    def __init__(self):
        seebug_url = "https://www.seebug.org/vuldb/vulnerabilities?page=1"

        super().__init__('Seebug', seebug_url)

    @staticmethod
    def random_delay(start, end):
        time.sleep(random.uniform(start, end))

    @retry()
    def fetch_data(self):
        options = Options()
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)

        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        url = "https://www.seebug.org/vuldb/vulnerabilities?page=1"
        driver.get(url)

        self.random_delay(2, 5)

        xpath = "/html/body/div[2]/div/div/div/div/table/tbody/tr[1]/td[4]/a"
        try:
            element = WebDriverWait(driver, 600).until(
                EC.visibility_of_element_located((By.XPATH, xpath))
            )
            self.random_delay(1, 3)
            html = driver.page_source
        except Exception as e:
            print(f"crawling {url} err: {e}")
            return ""
        finally:
            driver.quit()

        return html

    def parse_data(self, raw_data):
        vulnerabilities = []
        severity_mapping = {
            '低危': 'low',
            '中危': 'medium',
            '高危': 'high'
        }

        soup = BeautifulSoup(raw_data, 'html.parser')
        rows = soup.select('tbody tr')

        for row in rows:
            cols = row.find_all('td')
            ssv_id = cols[0].text.strip().split('-')[1]
            severity_cn = cols[2].div['data-original-title'] if cols[2].div else ''
            severity_en = severity_mapping[severity_cn]
            vul_name = cols[3].a.text.strip()
            cve_tmp = cols[4].find_all('i')[0]['data-original-title'] if cols[4].find_all('i') else ''
            cve = "" if "无" in cve_tmp else cve_tmp
            vulnerability = {
                'name': vul_name,
                'cve': cve,
                'severity': severity_en,
                'description': '',
                'source': self.source_name,
                'date': datetime.date.today().strftime("%Y-%m-%d"),
                'link': "https://www.seebug.org/vuldb/ssvid-"+ssv_id
            }
            vulnerabilities.append(vulnerability)

        return vulnerabilities
