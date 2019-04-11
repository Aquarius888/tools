# TODO: add logging
# TODO: add catcher of exceptions

import requests
from elasticsearch import Elasticsearch, RequestsHttpConnection, exceptions
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
def graphite_prefix_format(input):
    """
    Parse input, extract prefix (query) from brackets and separate not needed symbols
    :param input: grafana prefix (query) with grafana functions
    :return: clear prefix
    """
    # grafana variable pattern
    var_pattern = r'\$\w+'
    prefix = re.sub(var_pattern, '*', input)

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
        # Parser works ONLY for 'graph' type of panels
        if panel['type'] != 'graph':
            continue

        if 'datasource' in panel and 'Mixed' not in panel['datasource']:
            datasource = panel['datasource']
        else:
            datasource = 'default'

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
            datasource_set = pretty_search(target_list, 'datasource')
            if datasource_set:
                datasource = datasource_set[0]

            meta_dash = Meta_dash(panel['id'], panel['title'], datasource, target_list)
            meta_list.append(meta_dash)
    return meta_list


def ref_id(target_json):
    return pretty_search(target_json, 'refId')[0]


def prefix_extract(target_json):
    prfx = pretty_search(target_json, 'query')
    if not prfx:
        prfx = pretty_search(target_json, 'target')
    return prfx[0]


def elastic_query_format(query_str):
    """
    Get input, parse it, clean special symbols, compose list of clean query
    :param query_str: input, dirty string with query
    :return: list of clean query
    """
    meta_symbols = r'[?*+]'
    range_symbols = r'\[(\S*)\sTO\s(\S*)\]'
    list_request = []
    queries = query_str.split('AND')
    for qr in queries:
        # check that elasticsearch query contains special symbols
        if re.search(meta_symbols, qr):
            continue

        key, value = qr.split(':')

        # range handler
        if re.search(range_symbols, qr):
            resp = re.search(range_symbols, qr)
            list_request.append({'range': {key.strip(): {'gte': int(resp.group(1)), 'lte': int(resp.group(2))}}})
            continue

        # remove double quotes around value
        if re.search(r'\"', value):
            value = value.strip('"')
        list_request.append({'match': {key.strip(): value.strip()}})
    return list_request


def elastic_request(elk_url, index_tmpl, query, timewindow, proxy=''):
    """
    Make a request to Elasticsearch
    :param elk_url:
    :param index_tmpl:
    :param query:
    :param timewindow: time window in seconds
    :return:
    """

    gte = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time()-timewindow))
    lte = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time()))

    # list of rules should be extended if it is necessary
    if '9200' in elk_url:
        elk_url = elk_url.replace('9200', '80/elasticsearch')
    if 'elasticsearch-odh-ecx' in elk_url:
        elk_url = 'http://172.23.29.161:80/elasticsearch'
    if 'kibana-cdnrep' in elk_url:
        elk_url = 'http://kibana-cdnrep:80/elasticsearch'

    try:
        client = Elasticsearch(hosts=[elk_url],
                               connection_class=RequestsHttpConnection,
                               proxies=proxy,
                               timeout=120)
        client.ping()
        body = {'query': {'bool': {'filter': {'range': {'@timestamp': {"gte": gte, "lte": lte}}}, 'must': query}}}
        response = client.search(index=index_tmpl, body=body)
        return response['hits']['hits']
    except exceptions.ConnectionError as er:
        return er


# TODO: add the catcher to functions
def catch_http_error(response):
    try:
        response.raise_for_status()
    except response.exceptions.HTTPError as er:
        return "Error: {error}".format(error=er)
    pass


class GrafanaMaker:
    """
    Grafana API wrapper
    """

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
        Make a request about dashboard info by name
        :param name_dash: Grafana dashboard's general name
        :return: tuple (dashboards id, dashboards uid)
        """
        composed_url = '{base}/search?query={dash}'.format(
            base=self.url_api,
            dash=name_dash
        )
        response = self.session.get(composed_url)
        return response.json()[0]['id'], response.json()[0]['uid']

    def get_panels_info(self, uid):
        """
        Make a request about dashboard panels
        :param uid: panel uid
        :return: json with panel info
        """
        composed_url = '{base}/dashboards/uid/{uid}'.format(
            base=self.url_api,
            uid=uid
        )
        response = self.session.get(composed_url)
        panels = response.json()['dashboard']['panels']
        return panels

    def datasource(self, datasource_name):
        """
        Get a data source info by name
        :param datasource_name: name of datasource
        :return: json with id, name, url and etc of datasource
        """
        composed_url = '{base}/datasources/name/{name}'.format(
            base=self.url_api,
            name=datasource_name
        )
        response = self.session.get(composed_url)
        return response.json()

    def datasource_by_id(self, datasource_id):
        """
        Get a data source info by id
        :param datasource_name: id of datasource
        :return: json with id, name, url and etc of datasource
        """
        composed_url = '{base}/datasources/{id}'.format(
            base=self.url_api,
            id=datasource_id
        )
        response = self.session.get(composed_url)
        return response.json()

    def create_annotation(self, dash_id, panel_id, ref_id, timewindow):
        """
        Create an annotation for panel with tag and description
        :param dash_id: id of dashboard
        :param panel_id: id of panel
        :param ref_id: letter of Grafana query
        :param timewindow: checked timewindow
        :return: just reference (json) that an annotation has been created
        """
        composed_url = '{base}/annotations'.format(base=self.url_api)
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
        """
        Make a request to Graphite via Grafana
        :param prefix: metric query (or target) in graphite format
        :param datasource_id: id of datasource
        :return: json with data about requested metric
        """
        request = {
            'target': prefix,
            'format': 'json',
            'from': '-1h',
            'until': 'now',
            'maxDataPoints': 100
        }

        return self._get_proxy_call(datasource_id, 'render', request)

    @staticmethod
    def graphite_checker(response):
        """
        Checks a request about data presence
        :param response: graphite data (in json) with information about query for timewindow
        :return: list of tuple with note about data presence
        """
        data_lst = []
        for target in range(len(response)):
            datapoints = response[target]['datapoints']
            counter = 0
            for data_p in datapoints:
                if data_p[0] is not None:
                    counter += 1
            if counter == 0:
                data_lst.append((response[target]['target'], 'NO DATA'))
            else:
                data_lst.append((response[target]['target'], 'Checked'))
        return data_lst

    def influxdb_query(self, prefix, database, datasource_id):
        """
        Make a request to InfluxDB via Grafana
        :param prefix: metric query in InfluxDB format
        :param database: influxbd database name
        :param datasource_id: id of datasource
        :return: json with data about requested metric
        """
        request = {
            'q': prefix,
            'db': database,
            'epoch': 'ms'
        }

        return self._get_proxy_call(datasource_id, 'query', request)

    @staticmethod
    def influx_checker(response):
        """
        Checks a request about data presence
        :param response: influxdb data (in json) with information about query for timewindow
        :return: list of tuple with note about data presence
        """
        data_lst = []
        series = response['results'][0]['series'][0]

        datapoints = series['values']
        counter = 0
        for data_p in datapoints:
            if data_p[1] is not None:
                counter += 1
        if counter == 0:
            data_lst.append((series['name'], 'NO DATA'))
        else:
            data_lst.append((series['name'], 'Checked'))

        return data_lst

    def _get_proxy_call(self, datasource_id, query, request):
        """
        Make Grafana API proxy call
        :param datasource_id: id of datasource
        :param query: special word
        :param request: request
        :return: response in json
        """
        response = self.session.post('{base}/datasources/proxy/{datasource_id}/{query}'.format(
            base=self.url_api,
            datasource_id=datasource_id,
            query=query),
            params=request)

        try:
            response.raise_for_status()
        except request.exceptions.HTTPError as er:
            return "Error: {error}".format(error=er)

        return response.json()


# default timewindow in sec
TIMEWINDOW = 14400
# matching time prefix and seconds
timeprefix = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
# current time in ms
current_timestamp = int(time.time()*1000)

# datastructures
Meta_dash = namedtuple('Meta_dash', ['panel_id', 'title', 'datasource', 'target_json'])
Id_dash = namedtuple('Id_dash', ['name', 'id', 'uid'])

# create object - instance for work with Grafana
graf_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers)

id_info_list = [Id_dash(dash,
                        graf_inst.get_uid(dash)[0],
                        graf_inst.get_uid(dash)[1])
                for dash in settings.dash_list]

for dash_id_info in id_info_list:
    print('Dashboard \"{name}\" is on checking now'.format(name=dash_id_info.name))
    print('-------------------------------------------------')

    for meta_dash in panel_info(graf_inst.get_panels_info(dash_id_info.uid)):
        # convert relevant time in title if it exists
        reg = re.search(r'\s\(\d+[dhms]\)', meta_dash.title)
        if reg:
            timestring = reg.group().strip('( )')
            timewindow = int(re.search(r'\d+', timestring).group()) * \
                         timeprefix.get(re.search(r'\D', timestring).group())
        else:
            timewindow = TIMEWINDOW

        # handler of Grafana datasource name
        if 'default' in meta_dash.datasource:
            datasource_info = graf_inst.datasource(settings.default_datasource_name)
        else:
            datasource_info = graf_inst.datasource(meta_dash.datasource)
        datasource_id = datasource_info['id']

        # Graphite flow
        if 'graphite' in datasource_info['type']:

            # get clear string of prefix
            prefix = graphite_prefix_format(prefix_extract(meta_dash.target_json))
            metric_data = graf_inst.graphite_query(prefix, datasource_id)

            no_data = 0
            for query in graf_inst.graphite_checker(metric_data):
                if 'NO DATA' in query:
                    no_data += 1

            if no_data == len(graf_inst.graphite_checker(metric_data)):
                graf_inst.create_annotation(dash_id_info.id,
                                            meta_dash.panel_id,
                                            ref_id(meta_dash.target_json),
                                            timewindow)
                print("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                      format(dashboard=dash_id_info.name, panel=meta_dash.title))

        # Elasticsearch flow
        if 'elasticsearch' in datasource_info['type']:
            # derive elasticsearch url
            datasource_url = datasource_info['url']
            # derive elasticsearch index and convert to template
            index_templ = datasource_info['database']
            if re.search(r'\[\S+\]', datasource_info['database']):
                index_templ = re.search(r'\[\S+\]', datasource_info['database']).group().strip('[]') + '*'

            # derive elasticsearch query
            elastic_query = pretty_search(meta_dash.target_json, 'query')[0]
            query = elastic_query_format(elastic_query)

            elk_response = elastic_request(datasource_url, index_templ, query, timewindow, settings.proxy)

            if not elk_response:
                graf_inst.create_annotation(dash_id_info.id,
                                            meta_dash.panel_id,
                                            ref_id(meta_dash.target_json),
                                            timewindow)
                print("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                      format(dashboard=dash_id_info.name, panel=meta_dash.title))

        # InfluxDB flow
        if 'influxdb' in datasource_info['type']:
            timefilter = 'time >= now() - {timewindow}m'.format(timewindow=str(int(timewindow/60)))
            prefix = re.sub(r'\$\S*timeFilter', timefilter, prefix_extract(meta_dash.target_json))
            # GROUP BY replacement
            prefix = re.sub(r'\$\S*interval', '30s', prefix)
            metric_data = graf_inst.influxdb_query(prefix, datasource_info['database'], datasource_id)

            no_data = 0
            for query in graf_inst.influx_checker(metric_data):
                if 'NO DATA' in query:
                    no_data += 1

            # Seems like that there is only one query per graph for influxdb
            if no_data == len(graf_inst.influx_checker(metric_data)):
                graf_inst.create_annotation(dash_id_info.id,
                                            meta_dash.panel_id,
                                            ref_id(meta_dash.target_json),
                                            timewindow)
                print("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                      format(dashboard=dash_id_info.name, panel=meta_dash.title))

