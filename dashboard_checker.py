import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import json
from collections import namedtuple
import settings


def pretty_search(dict_or_list, key_to_search, search_for_first_only=False):
    """
    Give it a dict or a list of dicts and a dict key (to get values of),
    it will search through it and all containing dicts and arrays
    for all values of dict key you gave, and will return you set of them
    unless you wont specify search_for_first_only=True

    :param dict_or_list:
    :param key_to_search:
    :param search_for_first_only:
    :return:
    """
    search_result = set()
    if isinstance(dict_or_list, dict):
        for key in dict_or_list:
            key_value = dict_or_list[key]
            if key == key_to_search:
                if search_for_first_only:
                    return key_value
                else:
                    search_result.add(key_value)
            if isinstance(key_value, dict) or isinstance(key_value, list) or isinstance(key_value, set):
                _search_result = pretty_search(key_value, key_to_search, search_for_first_only)
                if _search_result and search_for_first_only:
                    return _search_result
                elif _search_result:
                    for result in _search_result:
                        search_result.add(result)
    elif isinstance(dict_or_list, list) or isinstance(dict_or_list, set):
        for element in dict_or_list:
            if isinstance(element, list) or isinstance(element, set) or isinstance(element, dict):
                _search_result = pretty_search(element, key_to_search, search_result)
                if _search_result and search_for_first_only:
                    return _search_result
                elif _search_result:
                    for result in _search_result:
                        search_result.add(result)
    return search_result if search_result else None


def prefix_format(prefix):
    return prefix.split('(')[prefix.count('(')].split(')')[0]


def graphite_request(session, url, prefix, timewindow):
    composed_url = '{0}/render/?target={1}&from=-{2}&format=json'.format(url, prefix, timewindow)
    response = session.get(composed_url)
    return response.json()


def graphite_checker(response):
    for target in range(len(response)):
        datapoints = response[target]['datapoints']
        pointer = 0
        for data_p in datapoints:
            if data_p[0] is not None:
                pointer += 1
        if pointer == 0:
            print(response[target]['target'], timewindow, 'NO DATA')
        else:
            print(response[target]['target'], timewindow, 'Checked')


def elk_chckr():
    pass


def influx_chckr():
    pass


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
        return response.json()[0]['uid']

    def graphite_dashinfo(self, uid):
        composed_url = '{0}/dashboards/uid/{1}'.format(self.url_api, uid)
        response = self.session.get(composed_url)
        panels = response.json()['dashboard']['panels']

        target = []
        datasource = 'default'

        for id in range(len(panels)):
            if 'datasource' in panels[id]:
                datasource = panels[id]['datasource']

            if len(panels[id]['targets']) > 1:
                for i in range(len(panels[id]['targets'])):
                    prefix = pretty_search(panels[id]['targets'][i], 'target').pop()
                    if '(' or ')' in prefix:
                        prefix = prefix_format(prefix)
                    meta_dash = Meta_dash(panels[id]['title'], datasource, prefix)
                    target.append(meta_dash)
            else:
                prefix = pretty_search(panels[id]['targets'], 'target').pop()
                if '(' and ')' in prefix:
                    prefix = prefix_format(prefix)
                meta_dash = Meta_dash(panels[id]['title'], datasource, prefix)
                target.append(meta_dash)
        return target

    def datasource_url(self, datasource_name):
        composed_url = '{0}/datasources/name/{1}'.format(self.url_api, datasource_name)
        response = self.session.get(composed_url)
        return response.json()



Meta_dash = namedtuple('Meta_dash', ['title', 'datasource', 'prefix'])

graf = GrafanaChecker(settings.url_api, settings.proxy, settings.headers)
uid = graf.get_uid(settings.dash_list[0])

# [print(aim) for aim in graf.graphite_dashinfo(uid)]


# print(graf.datasource_url(datasource_name))

# default graphite datasource
datasource_name = 'http://graphite-islogs'
with requests.Session() as session:
    timewindow = '10min'
    for meta_dash in graf.graphite_dashinfo(uid):
        if meta_dash.datasource is not 'default':
            datasource_name = graf.datasource_url(meta_dash.datasource)['url'].replace('/api', '')
            # print(datasource_name)
        if 'graphite' in datasource_name:
            # print(datasource_name)
            response = graphite_request(session, datasource_name, meta_dash.prefix, timewindow)
            graphite_checker(response)



