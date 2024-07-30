from .collector_edb import ExploitDBCollector
from .collector_msf import MSFCollector
from .collector_vulhub import VulhubCollector
from .collector_poc import POCCollector
from .collector_afrog import AfrogCollector
from .collector_packetstorm import PacketStormCollector
from .collector_oscs import OSCSCollector
from .collector_ali import AliCollector
from .collector_qax import QAXCollector
from .collector_threatbook import ThreatBookCollector
from .collector_github import GitHubCollector


class VulnerabilityManager:
    def __init__(self):
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

    def collect_vulnerabilities(self, selected_collectors=None):
        if not selected_collectors:
            selected_collectors = self.collector_classes.keys()
        selected_collectors_instances = [self.collector_classes[name]() for name in selected_collectors if
                                         name in self.collector_classes]
        all_vulnerabilities = []
        for collector in selected_collectors_instances:
            vulnerabilities = collector.collect_vulnerabilities()
            all_vulnerabilities.extend(vulnerabilities)
        return all_vulnerabilities

    def store_vulnerabilities(self, vulnerabilities):
        # 这里存储漏洞到数据库
        pass

    def process_vulnerabilities(self, selected_collectors=None):
        vulnerabilities = self.collect_vulnerabilities(selected_collectors)
        self.store_vulnerabilities(vulnerabilities)
