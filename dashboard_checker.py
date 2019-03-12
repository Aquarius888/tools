import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import time
import json
from collections import namedtuple
import settings


current_timestamp = int(time.time()*1000)


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


# TODO: review, may be it is needed to replace on regex
def prefix_format(prefix):
    """
    Parses input, extract prefix (query) from brackets and separate not needed symbols
    :param prefix: grafana prefix (query) with grafana functions
    :return: clear prefix
    """
    clear_prefix = prefix.split('(')[prefix.count('(')].split(')')[0]
    if ',' in clear_prefix:
        clear_prefix = clear_prefix.split(',')[0]
    return clear_prefix


def panel_info(panels_info):
    """

    :param panels_info: json from Grafana's request
    :return: list of namedtuples with info for checked panels
    """
    meta_list = []

    for id in range(len(panels_info)):

        if 'datasource' in panels_info[id]:
            datasource = panels_info[id]['datasource']
        else:
            datasource = 'default'

        target_list = panels_info[id]['targets']

        if len(target_list) > 1:
            for target in target_list:
                # don't execute if query is disabled
                hide = pretty_search(target, 'hide')
                if hide and True in hide:
                    continue

                # global datasource is Mixed
                # if 'Mixed' in datasource:
                if 'datasource' in target:
                    datasource = target['datasource']

                # extract prefix for graphite or query for influx and elastic
                prefix = pretty_search(target, 'query')
                if not prefix:
                    prefix = pretty_search(target, 'target')

                # extract value from set
                prefix = prefix.pop()
                ref_id = pretty_search(target, 'refId').pop()

                meta_dash = Meta_dash(panels_info[id]['id'], panels_info[id]['title'], datasource, ref_id, prefix)
                meta_list.append(meta_dash)
        else:
            # don't execute if query is disabled
            hide = pretty_search(target_list, 'hide')
            if hide and True in hide:
                continue

            # case: one query on panel, but global datasource is Mixed
            #if 'Mixed' in datasource:
            if 'datasource' in target:
                datasource = pretty_search(target_list, 'datasource').pop()

            # extract prefix for graphite or query for influx and elastic
            prefix = pretty_search(target_list, 'query')
            if not prefix:
                prefix = pretty_search(target_list, 'target')

            # extract value from set
            prefix = prefix.pop()
            ref_id = pretty_search(target_list, 'refId').pop()

            meta_dash = Meta_dash(panels_info[id]['id'], panels_info[id]['title'], datasource, ref_id, prefix)
            meta_list.append(meta_dash)
    return meta_list


def graphite_request(session, url, prefix, timewindow):
    """
    Makes a request to Graphite about data in (target) 'prefix' for timewindow
    :param session: requests session with Graphite server
    :param url: url of Graphite server
    :param prefix: path (prefix) identifying one or several metrics
    :param timewindow: relative timewindow (for ex, if it is 4h, it means 'last 4 hours')
    :return: response in json
    """
    composed_url = '{0}/render/?target={1}&from=-{2}&format=json'.format(url, prefix, timewindow)
    response = session.get(composed_url)
    return response.json()


def graphite_checker(response):
    """
    Checks a request about data existential
    :param response: graphite data (in json) with information about query for timewindow
    :return: list of tuple with note about data existential
    """
    data_lst = []
    for target in range(len(response)):
        datapoints = response[target]['datapoints']
        pointer = 0
        for data_p in datapoints:
            if data_p[0] is not None:
                pointer += 1
        if pointer == 0:
            data_lst.append((response[target]['target'], 'NO DATA'))
        else:
            data_lst.append((response[target]['target'], 'Checked'))
    return data_lst


def elk_chckr():
    pass


def influx_chckr():
    pass


class GrafanaMaker:

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
        """
        Function requests about dashboard info by name of it
        :param name_dash: Grafana dashboard's general name
        :return: tuple (dashboards id, dashboards uid)
        """
        composed_url = '{0}/search?query={1}'.format(self.url_api, name_dash)
        response = self.session.get(composed_url)
        return response.json()[0]['id'], response.json()[0]['uid']

    def get_panels_info(self, uid):
        composed_url = '{0}/dashboards/uid/{1}'.format(self.url_api, uid)
        response = self.session.get(composed_url)
        panels = response.json()['dashboard']['panels']
        return panels

    def datasource_url(self, datasource_name):
        composed_url = '{0}/datasources/name/{1}'.format(self.url_api, datasource_name)
        response = self.session.get(composed_url)
        return response.json()

    def create_annotation(self, dash_id, panel_id, ref_id, timewindow):
        composed_url = '{0}/annotations'.format(self.url_api)
        payload = {"dashboardId": dash_id,
                   "panelId": panel_id,
                   "time": current_timestamp,
                   "isRegion": False,
                   "timeEnd": 0,
                   "tags": ["NO DATA"],
                   "text": "No DATA for {0} at least last {1}".format(ref_id, timewindow)}
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        response = self.session.post(composed_url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        return response.text


# TODO: describe default and 'personal' (extract from panel title and multiple on N) timewindow
Meta_dash = namedtuple('Meta_dash', ['panel_id', 'title', 'datasource', 'ref_id', 'prefix'])
Id_dash = namedtuple('Id_dash', ['name', 'id', 'uid', 'timewindow'])

graf_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers)

id_info_list = [Id_dash(dash[0],
                        graf_inst.get_uid(dash[0])[0],
                        graf_inst.get_uid(dash[0])[1],
                        dash[1])
                for dash in settings.dash_list]

for dash_id_info in id_info_list:
    print('====================================================')
    #print(graf_inst.get_panels_info(dash_id_info.uid))

    for meta_dash in panel_info(graf_inst.get_panels_info(dash_id_info.uid)):

        # default datasource
        datasource_name = 'http://graphite-islogs'

        if 'default' not in meta_dash.datasource:
            # print(meta_dash.datasource)
            datasource_name = graf_inst.datasource_url(meta_dash.datasource)['url'].replace('/api', '')

        # flow for Graphite
        if 'graphite' in datasource_name:

            # get clear string of prefix
            prefix = prefix_format(meta_dash.prefix)
            meta_dash = meta_dash._replace(prefix=prefix)

            # with requests.Session() as session:
            #     metric_data = graphite_request(session, datasource_name, meta_dash.prefix, dash_id_info.timewindow)
            #
            #     no_data = 0
            #     for query in graphite_checker(metric_data):
            #         if 'NO DATA' in query:
            #             no_data += 1
            #
            #     if no_data == len(graphite_checker(metric_data)):
            #         print(dash_id_info.name, meta_dash.title, graf_inst.create_annotation(dash_id_info.id,
            #                                                                                    meta_dash.panel_id,
            #                                                                                    meta_dash.ref_id,
            #                                                                                    dash_id_info.timewindow))
        print(meta_dash)
        print(datasource_name)

        # TODO: implement a flow when elasticsearch as datasource
        if 'elk' in datasource_name:
            pass

        # TODO: implement a flow when influxDB as datasource
        if 'influx' in datasource_name:
            pass



