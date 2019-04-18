# TODO: add command line keys, arguments handler (fire ?)
# TODO: dry run
# TODO: add handler of exceptions
# TODO: review Grafana math functions, for ex. 'asPercent'

import requests
from elasticsearch import Elasticsearch, RequestsHttpConnection, exceptions
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import os
import re
import time
import json
from collections import namedtuple
import logging
from logging.handlers import RotatingFileHandler

import settings


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
        try:
            return response.json()[0]['id'], response.json()[0]['uid']
        except IndexError:
            logger.debug("Dashboard \"{}\" doesn't exist".format(name_dash))
            return None

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

    def datasource(self, ds_name):
        """
        Get a data source info by name
        :param ds_name: name of data source
        :return: json with id, name, url and etc of data source
        """
        composed_url = '{base}/datasources/name/{name}'.format(
            base=self.url_api,
            name=ds_name
        )
        response = self.session.get(composed_url)
        return response.json()

    def datasource_by_id(self, ds_id):
        """
        Get a data source info by id
        :param ds_id: id of data source
        :return: json with id, name, url and etc of data source
        """
        composed_url = '{base}/datasources/{id}'.format(
            base=self.url_api,
            id=ds_id
        )
        response = self.session.get(composed_url)
        return response.json()

    def create_annotation(self, dash_id, panel_id, ref_id, tag):
        """
        Create an annotation for panel with tag and description
        :param dash_id: id of dashboard
        :param panel_id: id of panel
        :param ref_id: letter of Grafana query
        :param: tag: list of desired tags
        :return: just reference (json) that an annotation has been created
        """
        composed_url = '{base}/annotations'.format(base=self.url_api)
        payload = {"dashboardId": dash_id,
                   "panelId": panel_id,
                   "time": current_timestamp,
                   "isRegion": False,
                   "timeEnd": 0,
                   "tags": tag,
                   "text": "Query {} \n Annotation's been added automatically by dashboard-checker (DataOps team tool)".
                       format(ref_id)}
        response = self.session.post(composed_url, data=json.dumps(payload).encode('utf-8'))
        return response.text

    def find_annotation(self, gte, lte, dash_id, tag, limit=100):
        composed_url = '{base}/annotations?from={gte}&to={lte}&tags={tag}&limit={limit}&dashboardId={dash_id}'.format(
            base=self.url_api,
            gte=gte,
            lte=lte,
            tag=tag,
            limit=limit,
            dash_id=dash_id)
        response = self.session.get(composed_url)
        return response.json()

    def delete_annotation(self, annot_id):
        composed_url = '{base}/annotations/{id}'.format(
            base=self.url_api,
            id=annot_id)
        response = self.session.delete(composed_url)
        return response.json()

    def graphite_query(self, prefix, ds_id, time_window):
        """
        Make a request to Graphite via Grafana
        :param prefix: metric query (or target) in graphite format
        :param ds_id: id of datasource
        :param time_window:
        :return: json with data about requested metric
        """
        request = {
            'target': prefix,
            'format': 'json',
            'from': '-{timewindow}s'.format(timewindow=time_window),
            'until': 'now',
            'maxDataPoints': 1000
        }
        return self._get_proxy_call(ds_id, 'render', request)

    @staticmethod
    def graphite_checker(response):
        """
        Checks a request about data presence
        :param response: graphite data (in json) with information about query for timewindow
        :return: list of tuple with note about data presence
        """
        data_lst = []
        for target in range(len(response)):

            try:
                datapoints = response[target]['datapoints']
            except TypeError as err:
                logging.debug("Exception has been raised in graphite_checker function, {}".format(err))
                continue

            counter = 0
            for data_p in datapoints:
                if data_p[0] is not None:
                    counter += 1
            if counter == 0:
                data_lst.append((response[target]['target'], 'NO DATA'))
            else:
                data_lst.append((response[target]['target'], 'Checked'))
        return data_lst

    def influxdb_query(self, prefix, database, ds_id):
        """
        Make a request to InfluxDB via Grafana
        :param prefix: metric query in InfluxDB format
        :param database: influxbd database name
        :param ds_id: id of datasource
        :return: json with data about requested metric
        """
        request = {
            'q': prefix,
            'db': database,
            'epoch': 'ms'
        }

        return self._get_proxy_call(ds_id, 'query', request)

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

    def _get_proxy_call(self, ds_id, query, request):
        """
        Make Grafana API proxy call
        :param ds_id: id of datasource
        :param query: special word
        :param request: request
        :return: response in json
        """
        response = self.session.post('{base}/datasources/proxy/{datasource_id}/{query}'.format(
            base=self.url_api,
            datasource_id=ds_id,
            query=query),
            params=request)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as er:
            return "Error: {error}".format(error=er)

        return response.json()


def configure_logging(log_level):
    logger = logging.getLogger(__name__)

    level = logging.getLevelName(log_level)
    logger.setLevel(level)

    format_str = '%(asctime)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(fmt=format_str)

    log_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dashboard_checker.log')
    rotating_hndlr = RotatingFileHandler(filename=log_path, maxBytes=5*1024*1024, backupCount=2)
    rotating_hndlr.setFormatter(formatter)
    # workaround - avoid duplication of log records, review is required
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.addHandler(rotating_hndlr)

    return logger


def pretty_search(dict_or_list, key_to_search, search_for_first_only=False):
    """
    Give it a dict or a list of dicts and a dict key (to get values of),
    it will search through it and all containing dicts and arrays
    for all values of dict key you gave, and will return you set of them
    unless you wont specify search_for_first_only=True

    :param dict_or_list:
    :param key_to_search:
    :param search_for_first_only:
    :return: list of results or None
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


def graphite_prefix_format(inpt):
    """
    Parse input, extract prefix (query) from brackets and separate not needed symbols
    :param inpt: grafana prefix (query) with grafana functions
    :return: clear prefix
    """
    # grafana variable pattern
    var_pattern = r'\$\w+'
    prefix = re.sub(var_pattern, '*', inpt)

    clear_prefix = prefix.split('(')[prefix.count('(')].split(')')[0]
    if ',' in clear_prefix:
        clear_prefix = clear_prefix.split(',')[0]

    return clear_prefix


def panel_info(panels_info):
    """
    Parse panel info and compose list of namedtuple with info for checked panels
    :param panels_info: json of Grafana's response, info about all panels for one dashboard
    :return: list of namedtuples (id, title, datasource, target_json info)
    """
    meta_list = []

    for panel in panels_info:
        # Parser works ONLY for 'graph' type of panels
        if panel['type'] != 'graph':
            continue

        try:
            datasource = panel['datasource']
        except KeyError:
            logger.debug("Datasource for {} doesn't exist, doesn't define or Mixed type, will be assigned as 'default'".
                         format(panel['title']))
            # Seems like it is a bug in Grafana
            datasource = 'default'
            # continue

        if datasource is None:
            # Seems like it is a bug in Grafana
            logger.debug(
                "Datasource for {} is None. , will be assigned as 'default'".format(panel['title']))
            datasource = 'default'

        if 'Mixed' in datasource:
            logger.debug("Datasource for {} is Mixed. Will be assigned as 'default'".format(panel['title']))
            datasource = 'default'

        logging.debug(panel['title'], datasource)

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

        key, value, *_ = qr.split(':')

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


def elastic_request(elk_url, index_tmpl, query, time_window, proxy=''):
    """
    Make a request to Elasticsearch
    :param elk_url:
    :param index_tmpl:
    :param query:
    :param time_window: time window in seconds
    :param proxy:
    :return: list of hits
    """

    gte = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time()-time_window))
    lte = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time()))

    # list of rules should be extended if it is necessary
    if '9200' in elk_url:
        elk_url = elk_url.replace('9200', '80/elasticsearch')
    if 'elasticsearch-odh-ecx' in elk_url:
        elk_url = 'http://172.23.29.161:80/elasticsearch'

    # if 'kibana-cdnrep' in elk_url:
    #     elk_url = 'http://kibana-cdnrep:80/elasticsearch'
    # if 'kibana-mercury' in elk_url:
    #     elk_url = 'http://kibana-mercury:80/elasticsearch'

    if '80' not in elk_url:
        elk_url = 'http://{}:80/elasticsearch'.format(elk_url.split('/')[2])

    try:
        client = Elasticsearch(hosts=[elk_url],
                               connection_class=RequestsHttpConnection,
                               proxies=proxy,
                               timeout=120)
        # client.ping()
        body = {'query': {'bool': {'filter': {'range': {'@timestamp': {"gte": gte, "lte": lte}}}, 'must': query}}}
        response = client.search(index=index_tmpl, body=body)
        return response['hits']['hits']
    except exceptions.ConnectionError as er:
        logging.debug(er)
        return None


# TODO: add the catcher to functions
def catch_http_error(response):
    try:
        response.raise_for_status()
    except response.exceptions.HTTPError as er:
        return "Error: {error}".format(error=er)
    pass


def annotation_handler(time_window, dash_id, tag='NO DATA'):
    """
    Handles Grafana of annotations, looks for annotations on dashboard according to its id and tag and deletes it
    :param time_window: time window for search annotations, in s
    :param dash_id: id of dashboard
    :param tag: tag of annotations
    :return:
    """
    annot_list = graf_inst.find_annotation(current_timestamp - time_window * 1000, current_timestamp, dash_id, tag)
    annotation_list_id = [annot.get('id') for annot in annot_list]
    for annot_id in annotation_list_id:
        graf_inst.delete_annotation(annot_id)
        logger.info("Annotation with id: {} has been deleted".format(annot_id))


def graphite_flow(time_window, tag=['NO DATA']):
    """
    Derives graphite metric's path, gets list of metric's data for specified time window, initializes request
    creates annotations if data is null
    :param time_window: time window for search annotations, in s
    :param tag: list of tags of annotations
    :return:
    """
    extract = pretty_search(meta_dash.target_json, 'target')
    prefix = graphite_prefix_format(extract[0])
    metric_data = graf_inst.graphite_query(prefix, datasource_id, time_window)

    no_data = 0
    checked_list = graf_inst.graphite_checker(metric_data)
    for query in checked_list:
        if 'NO DATA' in query:
            no_data += 1

    if no_data == len(checked_list):
        graf_inst.create_annotation(dash_id_info.id,
                                    meta_dash.panel_id,
                                    ref_id(meta_dash.target_json),
                                    tag)
        logger.info("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                    format(dashboard=dash_id_info.name, panel=meta_dash.title))


def elasticsearch_flow(time_window, tag=['NO DATA']):
    """
    Derives index and formats it to template (index-*), initializes request,
    creates annotations if data is null
    :param time_window: time window for search annotations, in s
    :param tag: list of tags of annotations
    :return:
    """
    index_templ = datasource_db
    if re.search(r'\[(\S+)\]', datasource_db):
        index_templ = re.search(r'\[(\S+)\]', datasource_db).group(1) + '*'

    elastic_query = pretty_search(meta_dash.target_json, 'query')[0]
    query = elastic_query_format(elastic_query)

    elk_response = elastic_request(datasource_url, index_templ, query, time_window, settings.proxy)

    if elk_response is None:
        pass

    if not elk_response:
        graf_inst.create_annotation(dash_id_info.id,
                                    meta_dash.panel_id,
                                    ref_id(meta_dash.target_json),
                                    tag)
        logger.debug("Elasticsearch query {} where there is no data".format(query))
        logger.info("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                    format(dashboard=dash_id_info.name, panel=meta_dash.title))


def influxdb_flow(time_window, tag=['NO DATA']):
    """
    Derives query, initializes request to InfluxDB and creates annotations if data is null
    :param time_window: time_window: time window for search annotations, in s
    :param tag: list of tags of annotations
    :return:
    """
    time_filter = 'time >= now() - {timewindow}m'.format(timewindow=str(int(time_window / 60)))
    extract = pretty_search(meta_dash.target_json, 'query')
    prefix = re.sub(r'\$\S*timeFilter', time_filter, extract[0])
    # GROUP BY replacement
    prefix = re.sub(r'\$\S*interval', '30s', prefix)
    metric_data = graf_inst.influxdb_query(prefix, datasource_db, datasource_id)

    no_data = 0
    for query in graf_inst.influx_checker(metric_data):
        if 'NO DATA' in query:
            no_data += 1

    if no_data == len(graf_inst.influx_checker(metric_data)):
        graf_inst.create_annotation(dash_id_info.id,
                                    meta_dash.panel_id,
                                    ref_id(meta_dash.target_json),
                                    tag)
        logger.info("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                    format(dashboard=dash_id_info.name, panel=meta_dash.title))


def relevant_time(title, skip='abs'):
    """
    Try to extract relevant time or skip pointer from title of panel
    :param skip: specifies that script skips checkinf of a panel
    :param title: title of panel
    :return: time window or None, in second
    """
    # convert relevant time in title if it exists
    pattern = r'\s\((\d*[dhms]|daily|hourly|minute|abs|per day|per hour|per min\D*)\)'
    relevant = re.search(pattern, title)

    if relevant:
        if skip in relevant.group():
            return None

        time_string = relevant.group(1)
        if re.search(r'\d+', time_string):
            time_window = int(re.search(r'\d*', time_string).group()) * TIMEPREFIX.get(
                re.search(r'\D', time_string).group())
        else:
            time_window = TIMEPREFIX.get(time_string)
    else:
        time_window = TIMEWINDOW
    return time_window


# default timewindow in sec
TIMEWINDOW = 14400
# matching time prefix and seconds
TIMEPREFIX = {'d': 86400,
              'h': 3600,
              'm': 60,
              's': 1,
              'per day': 86400,
              'per hour': 3600,
              'per min': 60,
              'per minute': 60,
              'daily': 86400,
              'minute': 60,
              'hourly': 3600}

# contains dashboard info: id of panel, title of panel, datasource for panel ...
Meta_dash = namedtuple('Meta_dash', ['panel_id', 'title', 'datasource', 'target_json'])
Id_dash = namedtuple('Id_dash', ['name', 'id', 'uid'])

if __name__ == '__main__':
    logger = configure_logging(settings.log_level)
    logger.info('-------------------------------------------------')

    # create object - instance for work with Grafana
    graf_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers)

    id_info_list = []
    for dash in settings.dash_list:
        try:
            id_info_list.append(Id_dash(dash, graf_inst.get_uid(dash)[0], graf_inst.get_uid(dash)[1]))
        except TypeError:
            continue

    for dash_id_info in id_info_list:
        logger.info('Dashboard \"{name}\" is on checking now'.format(name=dash_id_info.name))

        # current time in ms
        current_timestamp = int(time.time() * 1000)

        annotation_handler(TIMEPREFIX.get('d'), dash_id_info.id)

        # main flow: check data and set annotations
        for meta_dash in panel_info(graf_inst.get_panels_info(dash_id_info.uid)):
            logger.info("Panel \"{panel}\" (query \"{query}\") is checking...".
                        format(panel=meta_dash.title, query=ref_id(meta_dash.target_json)))

            timewindow = relevant_time(meta_dash.title)
            if timewindow is None:
                logger.info("Panel \"{panel}\" is uncheckable by notation 'abs'".format(panel=meta_dash.title))
                continue

            # handler of Grafana datasource name
            if 'default' in meta_dash.datasource:
                datasource_info = graf_inst.datasource(settings.default_datasource_name)
            else:
                datasource_info = graf_inst.datasource(meta_dash.datasource)

            datasource_id = datasource_info['id']
            datasource_url = datasource_info['url']
            datasource_db = datasource_info['database']

            if 'graphite' in datasource_info['type']:
                graphite_flow(timewindow)

            if 'elasticsearch' in datasource_info['type']:
                elasticsearch_flow(timewindow)

            if 'influxdb' in datasource_info['type']:
                influxdb_flow(timewindow)
