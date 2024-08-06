import datetime
import requests
from config import cfg
from .decorators import retry
from .utils import extract_cve, process_cves
from .base_collector import VulnerabilityCollector


class GitHubCollector(VulnerabilityCollector):
    def __init__(self):
        github_headers = {
            "Authorization": f"token {cfg['github']['token']}",
        }
        super().__init__('GitHub', "https://api.github.com/search/repositories")
        self.headers = github_headers

    @retry()
    def fetch_data(self):
        year = datetime.datetime.now().year
        params = {'q': f'CVE-{year}', 'sort': 'updated', 'per_page': 30, 'page': 1}
        response = requests.get(self.source_url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    def parse_data(self, raw_data):
        today = datetime.date.today().strftime("%Y-%m-%d")
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        vulnerabilities_dict = {}
        for repo in raw_data['items']:
            if repo['fork']:
                continue
            pushed_at = repo['pushed_at'].split('T')[0]
            if pushed_at != today and pushed_at != yesterday:
                continue
            push_date = datetime.datetime.strptime(repo['pushed_at'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
            cves = extract_cve(repo['name'])
            if not cves:
                continue
            content_url = repo['contents_url'].split("{")[0]
            res = requests.get(content_url)
            if res.status_code != 200:
                continue
            exists, desc, severity = process_cves(cves)
            if not exists:
                continue

            vulnerability = {
                'name': cves,
                'cve': cves,
                'severity': severity,
                'description': desc,
                'source': self.source_name,
                'date': push_date,
                'link': repo['html_url']
            }
            vulnerabilities_dict[vulnerability['name']] = vulnerability
        return list(vulnerabilities_dict.values())
