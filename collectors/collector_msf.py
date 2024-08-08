import datetime
import requests
import re
from config import cfg
from .decorators import retry
from .base_collector import VulnerabilityCollector


class MSFCollector(VulnerabilityCollector):
    """
    GitHub api will show 30 records by default
    get more data with params = {'since': since, 'page': page, 'per_page': 100}
    """

    def __init__(self):
        msf_url = "https://api.github.com/repos/rapid7/metasploit-framework/commits"
        msf_headers = {
            "Authorization": f"token {cfg['github']['token']}",
        }
        super().__init__('Metasploit', msf_url)
        self.headers = msf_headers

    @retry()
    def fetch_data(self, timeout):
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat() + 'Z'
        response = requests.get(self.source_url, params={'since': since}, headers=self.headers, timeout=timeout)
        response.raise_for_status()
        return response.json()

    @staticmethod
    @retry()
    def extract_info(file_path, timeout):
        if cfg['github']['proxy'] == '':
            url = f"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/{file_path}"
        else:
            url = f"{cfg['github']['proxy']}https://raw.githubusercontent.com/rapid7/metasploit-framework/master/{file_path}"
        response = requests.get(url, timeout=timeout)
        body = response.text

        description_pattern = re.compile(r"'Description'\s*=>\s*%q\{(.*?)\},", re.DOTALL)
        description_match = description_pattern.search(body)
        cleaned_description = ''
        if description_match:
            description = description_match.group(1).strip()
            cleaned_description = "\n".join([line.strip() for line in description.split("\n") if line.strip()])

        name_pattern = re.compile(r"'Name'\s*=>\s*'([^']*)'")
        name = name_pattern.search(body).group(1)
        cve_pattern = re.compile(r"(?:')(CVE)(?:', ')([0-9]{4}-[0-9]{4,10})(?:')")
        cve_matches = cve_pattern.findall(body)
        cves = [f"{match[0]}-{match[1]}" for match in cve_matches]
        cves_string = ",".join(cves)

        return name, cves_string, cleaned_description

    def parse_data(self, raw_data):
        vulnerabilities_dict = {}
        for commit in raw_data:
            commit_url = commit['url']
            commit_response = requests.get(commit_url, headers=self.headers)
            if commit_response.status_code == 200:
                commit_data = commit_response.json()
                files = commit_data['files']
                for file in files:
                    if file['filename'].endswith('.rb') and file['status'] == 'added' and file['filename'].split('/')[0] == 'modules' and file['filename'].split('/')[1] == 'exploits':
                        vulnerability = {
                            'name': self.extract_info(file['filename'])[0],
                            'cve': self.extract_info(file['filename'])[1],
                            'severity': 'high',
                            'description': self.extract_info(file['filename'])[2],
                            'source': self.source_name,
                            'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'link': "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/" + file[
                                'filename']
                        }
                        vulnerabilities_dict[vulnerability['name']] = vulnerability

        vulnerabilities = list(vulnerabilities_dict.values())
        return vulnerabilities
