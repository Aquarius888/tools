import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# from collections import namedtuple
import settings


class GrafanaChecker:

    def __init__(self, url_api, proxy, headers):
        self.url_api = url_api
        self.session = requests.Session()
        self.session.headers = headers
        self.session.proxies = proxy

        retry = Retry(connect=5, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def get_uid(self, name_dash):
        composed_url = '{0}/search?query={1}'.format(self.url_api, name_dash)
        response = self.session.get(composed_url)
        return response.json()

    def get_dashinfo(self):
        # retrun datasource, graph_title, prefix
        pass

    @staticmethod
    def checker(dash_lst):
        pass


headers = {"Authorization": "Bearer {}".format(settings.token)}
url_api = 'http://grafana-staging/api'
proxy = {}
meta_dash = ('Netflix', 14400)

graf = GrafanaChecker(url_api, proxy, headers)
print(graf.get_uid(meta_dash[0]))
