import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import re
import time
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
    search_result = list()
    if isinstance(dict_or_list, dict):
        for key in dict_or_list:
            key_value = dict_or_list[key]
            if key == key_to_search:
                if search_for_first_only:
                    return key_value
                else:
                    search_result.append(key_value)
            if isinstance(key_value, dict) or isinstance(key_value, list) or isinstance(key_value, set):
                _search_result = pretty_search(key_value, key_to_search, search_for_first_only)
                if _search_result and search_for_first_only:
                    return _search_result
                elif _search_result:
                    for result in _search_result:
                        search_result.append(result)
    elif isinstance(dict_or_list, list) or isinstance(dict_or_list, set):
        for element in dict_or_list:
            if isinstance(element, list) or isinstance(element, set) or isinstance(element, dict):
                _search_result = pretty_search(element, key_to_search, search_result)
                if _search_result and search_for_first_only:
                    return _search_result
                elif _search_result:
                    for result in _search_result:
                        search_result.append(result)
    return search_result if search_result else None


# TODO: review, replace on regex
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
    Parse info and compose list of namedtuple with info for checked panels
    :param panels_info: json of Grafana's response, info about all panels for one dashboard
    :return: list of namedtuples (id, title, datasource, target_json info)
    """
    meta_list = []

    for panel in panels_info:
        datasource = 'default'

        # Parser works ONLY for 'graph' type of panels
        if panel['type'] != 'graph':
            continue

        if 'datasource' in panel and 'Mixed' not in panel['datasource']:
            datasource = panel['datasource']

        target_list = panel['targets']

        if len(target_list) > 1:
            for target in target_list:
                # don't execute if query is disabled
                hide = pretty_search(target, 'hide')
                if hide and True in hide:
                    continue

                # global datasource is Mixed
                if 'datasource' in target:
                    datasource = target['datasource']

                meta_dash = Meta_dash(panel['id'], panel['title'], datasource, target)
                meta_list.append(meta_dash)
        else:
            # don't execute if query is disabled
            hide = pretty_search(target_list, 'hide')
            if hide and True in hide:
                continue

            # case: one query on panel, but global datasource is Mixed
            if 'datasource' in target_list:
                datasource = pretty_search(target_list, 'datasource')[0]

            meta_dash = Meta_dash(panel['id'], panel['title'], datasource, target_list)
            meta_list.append(meta_dash)
    return meta_list


def ref_id(target_json):
    return pretty_search(target_json, 'refId')[0]


def prefix(target_json):
    prfx = pretty_search(target_json, 'query')
    if not prfx:
        prfx = pretty_search(target_json, 'target')
    return prfx[0]


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


def elastic_checker(response):
    pass


def influx_checker(response):
    """
    Checks a request about data existential
    :param response: influxdb data (in json) with information about query for timewindow
    :return: list of tuple with note about data existential
    """
    data_lst = []
    series = response['results'][0]['series'][0]

    datapoints = series['values']
    pointer = 0
    for data_p in datapoints:
        if data_p[1] is not None:
            pointer += 1
    if pointer == 0:
        data_lst.append((series['name'], 'NO DATA'))
    else:
        data_lst.append((series['name'], 'Checked'))

    return data_lst


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

    def datasource(self, datasource_name):
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

    def graphite_query(self, prefix, datasource_id):
        request = {
            'target': prefix,
            'format': 'json',
            'from': '-1h',
            'until': 'now',
            'maxDataPoints': 100
        }
        response = self.session.post('{base}/datasources/proxy/{datasource_id}/render'.format(
            base=self.url_api,
            datasource_id=datasource_id),
            params=request)
        return response.json()

    def influxdb_query(self, prefix, database, datasource_id):
        request = {
            'q': prefix,
            'db': database,
            'epoch': 'ms'
        }
        response = self.session.post('{base}/datasources/proxy/{datasource_id}/query'.format(
            base=self.url_api,
            datasource_id=datasource_id),
            params=request)
        return response.json()

    def elastic_query(self, indices, timewindow, query, datasource_id):

        gte = int(time.time() - timewindow * 1000)
        lte = int(time.time())

        req_head = {
            "search_type": "query_then_fetch",
            "ignore_unavailable": True,
            "index": indices
        }

        bucket_aggs = pretty_search(query, 'bucketAggs')[0]
        elk_req = pretty_search(query, 'query')[0]
        aggs = {}
        bucket_aggs.reverse()

        substr = self._aggs_compose(aggs, bucket_aggs, gte, lte)

        req_body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [{
                        "range":
                            {
                                "@timestamp":
                                    {
                                        "gte": gte,
                                        "lte": lte,
                                        "format": "epoch_second"
                                    }
                            }
                    },
                        {"query_string":
                             {"analyze_wildcard": True,
                              "query": elk_req}}]}}, "aggs": {}}
        req_body['aggs'].update(substr)
        # print(json.dumps(request, indent=4))
        response = self.session.post('{base}/datasources/proxy/{datasource_id}/_msearch'.format(
            base=self.url_api,
            datasource_id=datasource_id),
            data=req_head,
            json=req_body)

        print(response.text)

    def _aggs_compose(self, aggs, bucket_aggs, gte, lte):
        aggs = {}
        while bucket_aggs:
            bucket = bucket_aggs.pop()

            if bucket['field'] == '@timestamp':
                terms = {}
                terms.update(bucket['settings'])
                terms['field'] = bucket['field']
                terms["extended_bounds"] = {"min": gte, "max": lte}
                terms["format"] = "epoch_second"
                aggs = {bucket['id']: {bucket['type']: terms}}
                aggs["aggs"] = self._aggs_compose(aggs, bucket_aggs, gte, lte)

            else:
                terms = {}
                terms.update(bucket['settings'])
                terms['field'] = bucket['field']
                aggs = {bucket['id']: {bucket['type']: terms}}
                aggs["aggs"] = self._aggs_compose(aggs, bucket_aggs, gte, lte)
        return aggs


# default timewindow in sec
timewindow = 14400
# matching time prefix and seconds
timeprefix = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
# current time in ms
current_timestamp = int(time.time() * 1000)
today = time.strftime("%Y.%m.%d", time.localtime())
##################################################################################

# datastructures
Meta_dash = namedtuple('Meta_dash', ['panel_id', 'title', 'datasource', 'target_json'])
Id_dash = namedtuple('Id_dash', ['name', 'id', 'uid'])
##################################################################################

# create object - instance for work with Grafana
graf_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers)

id_info_list = [Id_dash(dash,
                        graf_inst.get_uid(dash)[0],
                        graf_inst.get_uid(dash)[1])
                for dash in settings.dash_list]

for dash_id_info in id_info_list:
    print('Dashboard \"{name}\" is on checking now'.format(name=dash_id_info.name))

    for meta_dash in panel_info(graf_inst.get_panels_info(dash_id_info.uid)):

        # convert relevant time in title if it exists
        reg = re.search(r'\s\(\d+[dhms]\)', meta_dash.title)
        if reg:
            timestring = reg.group().strip('( )')
            timewindow = int(re.search(r'\d+', timestring).group()) * \
                         timeprefix.get(re.search(r'\D', timestring).group())

        if 'default' in meta_dash.datasource:
            datasource_info = graf_inst.datasource(settings.default_datasource_name)
        else:
            datasource_info = graf_inst.datasource(meta_dash.datasource)
        datasource_id = datasource_info['id']

        # flow for Graphite
        if 'graphite' in datasource_info['type']:

            # get clear string of prefix
            prefix = prefix_format(prefix(meta_dash.target_json))
            metric_data = graf_inst.graphite_query(prefix, datasource_id)

            no_data = 0
            for query in graphite_checker(metric_data):
                print(query)
                if 'NO DATA' in query:
                    no_data += 1

            if no_data == len(graphite_checker(metric_data)):
                graf_inst.create_annotation(dash_id_info.id,
                                            meta_dash.panel_id,
                                            ref_id(meta_dash.target_json),
                                            timewindow)
                print("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                      format(dashboard=dash_id_info.name, panel=meta_dash.title))

        # TODO: implement a flow when elasticsearch as datasource
        if 'elasticsearch' in datasource_info['type']:
            # assumption timedelta not more than one day (23:59:59)
            assert timewindow < 86400

            # create list of elasticsearch indices for today and 'today - timewindow'
            delta = time.strftime("%Y.%m.%d", time.localtime(time.time() - timewindow))
            index_templ = re.search(r'\[\S+\]', datasource_info['database']).group().strip('[]')
            elastic_indices_reserve = (index_templ + today, index_templ + delta)
            elastic_indices = [index for index in set(elastic_indices_reserve)]

            # it doesn't work now
            graf_inst.elastic_query(elastic_indices, timewindow, meta_dash.target_json, datasource_id)

        # influxdb flow
        if 'influxdb' in datasource_info['type']:
            # insert variable timewindow from graph title instead of 30m
            prefix = re.sub(r'\$\S*timeFilter', 'time >= now() - 30m', prefix(meta_dash.target_json))
            # GROUP BY replacement
            prefix = re.sub(r'\$\S*interval', '30s', prefix)

            metric_data = graf_inst.influxdb_query(prefix, datasource_info['database'], datasource_id)

            no_data = 0
            for query in influx_checker(metric_data):
                if 'NO DATA' in query:
                    no_data += 1

            # Seems like that there is only one query per graph for influxdb
            if no_data == len(influx_checker(metric_data)):
                graf_inst.create_annotation(dash_id_info.id,
                                            meta_dash.panel_id,
                                            ref_id(meta_dash.target_json),
                                            timewindow)
                print("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                      format(dashboard=dash_id_info.name, panel=meta_dash.title))

# TODO: review Grafana variables in prefix


