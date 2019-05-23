# TODO: search through folders
# TODO: search dashboards with tags
# TODO: variable's handler in query (influx)
# TODO: parallelization
# TODO: add wrong queries to email report

"""
The tool goes through dashboards (panel's type 'graph') and looks for gaps in data,
in this case, adds an annotation on a panel.

Usage:
python3 dashboard_checker.py (default run, doesn't delete old annotations, default time window and tag is 'NO DATA')
python3 dashboard_checker.py -c 86400 (deletes old annotation for last 24h (86400 seconds),
                                       default time window and tag is 'NO DATA')
python3 dashboard_checker.py -d graphite (goes through only graphite datasource panels,
                                       default time window and tag is 'NO DATA')
python3 dashboard_checker.py -t TAG (goes through all implemented datasources panels, create annotations with tag TAG)
python3 dashboard_checker.py -i (dry run, test mode)

Combinations of arguments are available.
"""
import requests
from argparse import ArgumentParser
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import os
import re
import time
import json
from collections import namedtuple

import logging
from logging.handlers import RotatingFileHandler

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import settings
except ImportError as err:
    print("Make sure settings.py is in one directory with the tool. {err}".format(err=err))


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
        :return: list of tuples (dashboard title, dashboards id, dashboards uid)
        """
        id_uid = []
        composed_url = '{base}/search?query={dash}'.format(
            base=self.url_api,
            dash=name_dash
        )
        response = self.session.get(composed_url)

        try:
            for db in response.json():
                id_uid.append((db['title'], db['id'], db['uid']))
            return id_uid
        except IndexError:
            logger.debug("Dashboard \"{}\" doesn't exist".format(name_dash))
            return None

    def get_dashboard(self, uid):
        """
        Get dashboard's data
        :param uid: dashboard uid
        :return: json
        """
        composed_url = '{base}/dashboards/uid/{uid}'.format(
            base=self.url_api,
            uid=uid)
        response = self.session.get(composed_url)
        return response.json()['dashboard']

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
        :param: tag: list of desired tags (type: list)
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
        """
        Looks for annotations
        :param gte:
        :param lte:
        :param dash_id:
        :param tag:
        :param limit:
        :return:
        """
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
        """
        Removes old annotation
        :param annot_id: annotation id
        :return:
        """
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
                logger.debug("Exception has been raised in graphite_checker function, {}".format(err))
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

    def elastic_query(self, index_tmpl, query, time_window, ds_id):
        """
        Make a request to Elastic via Grafana proxy API
        :param index_tmpl: template (wildcard) of ES indices
        :param query: main part of 'must' query to ES
        :param time_window: time window
        :param ds_id: datasource id
        :return: json
        """

        gte = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - time_window))
        lte = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time()))

        index_part = '{"index":"%s"}' % index_tmpl
        body = '{"query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "%s", "lte": "%s"}}}, ' \
               '{"query_string": {"analyze_wildcard":true,"query": "%s"}}]}}}' % (gte, lte, query)
        data = '{index}\n{body}\n'.format(index=index_part, body=body)

        return self._get_proxy_call(ds_id, '_msearch', data)

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
            data=request)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as er:
            return "Error: {error}\n{text}".format(error=er, text=response.text)

        return response.json()


def configure_logging(log_level):
    """
    Configures logger
    :param log_level: logging level (INFO, DEBUG...)
    :return: object logger
    """
    logger = logging.getLogger(__name__)

    level = logging.getLevelName(log_level)
    logger.setLevel(level)

    format_str = '%(asctime)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(fmt=format_str)

    log_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dashboard_checker.log')
    rotating_hndlr = RotatingFileHandler(filename=log_path, maxBytes=5 * 1024 * 1024, backupCount=2)
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

        if datasource is None:
            # Seems like it is a bug in Grafana
            logger.debug(
                "Datasource for {} is None, will be assigned as 'default'".format(panel['title']))
            datasource = 'default'

        if 'Mixed' in datasource:
            logger.debug("Datasource for {} is Mixed. Will be assigned as 'default'".format(panel['title']))
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
    # Ref id without a letter (a lot of queries on a panel)
    try:
        return pretty_search(target_json, 'refId')[0]
    except TypeError:
        logger.debug("A lot of quires on a panel, ref_id doesn't have a letter")
        return 'One_more'


def annotation_handler(time_window, dash_id, tag, test_mode=False):
    """
    Handles Grafana of annotations, looks for annotations on dashboard according to its id and tag and deletes it
    :param time_window: time window for search annotations, in s
    :param dash_id: id of dashboard
    :param tag: tag of annotations
    :param test_mode: test mode
    :return:
    """
    annot_list = request_inst.find_annotation(current_timestamp - time_window * 1000, current_timestamp, dash_id, tag)
    annotation_list_id = [annot.get('id') for annot in annot_list]
    for annot_id in annotation_list_id:
        if test_mode is False:
            request_inst.delete_annotation(annot_id)
            logger.info("Annotation with id: {annot} has been deleted".format(annot=annot_id))
        else:
            logger.info("Annotation with id: {annot} is found on a dashboard id: {dash}".format(annot=annot_id,
                                                                                                dash=dash_id))


def graphite_flow(time_window, tag, test_mode=False):
    """
    Derive graphite metric's path, get list of metric's data for specified time window, initialize request
    create annotations if data is null
    :param time_window: time window for search annotations, in s
    :param tag: tag for annotations, type: string
    :param test_mode: test mode
    :return:
    """
    no_data = 0
    extract = pretty_search(meta_dash.target_json, 'targetFull')
    if extract is None or []:
        extract = pretty_search(meta_dash.target_json, 'target')

    prefix = extract[0]

    # variable's handler
    if '$' in prefix:
        split_prefix = prefix.split('.')
        for i in range(len(split_prefix)):
            if '$' in split_prefix[i]:
                split_prefix[i] = dashboard_vars.get(split_prefix[i].lstrip('$'))
        try:
            prefix = '.'.join(split_prefix)
        except TypeError as err:
            logger.debug('Wrong query?! Error: {} Check dashboard {}, panel {}, query {}'
                         .format(err,
                                 dash_id_info.name,
                                 meta_dash.title,
                                 ref_id(meta_dash.target_json)))
            report_preparation('- graphite broken query?')
            return None

    metric_data = request_inst.graphite_query(prefix, datasource_id, time_window)
    checked_list = request_inst.graphite_checker(metric_data)

    if not metric_data:
        logger.debug("Check graphite query, seems like it is not ready. Dash: {d}, panel: {p}, query: {q}".
                     format(d=dash_id_info.name,
                            p=meta_dash.title,
                            q=ref_id(meta_dash.target_json)))

    for query in checked_list:
        if 'NO DATA' in query:
            no_data += 1

    if no_data == len(checked_list):
        report_preparation()
        if test_mode is False:
            logger.debug(annotation_inst.create_annotation(dash_id_info.id,
                                                           meta_dash.panel_id,
                                                           ref_id(meta_dash.target_json),
                                                           [tag]))
            logger.debug(prefix)
            logger.info("Annotation has been added on dashboard \"{dashboard}\" panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_dash.title))
        else:
            # Test mode is activated
            logger.info("No data state is found on dashboard \"{dashboard}\" panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_dash.title))


def elasticsearch_flow(time_window, tag, test_mode=False):
    """
    Derive index and format it to template (index-*), initialize request,
    create annotations if data is null
    :param time_window: time window for search annotations, in s
    :param tag: tag for annotations, type: string
    :param test_mode: test mode
    :return:
    """
    index_templ = datasource_db
    if re.search(r'\[(\S+)\]', datasource_db):
        index_templ = re.search(r'\[(\S+)\]', datasource_db).group(1) + '*'

    elastic_query = pretty_search(meta_dash.target_json, 'query')[0]

    if '\"' in elastic_query:
        elastic_query = elastic_query.replace('\"', '\\"')

    # annotation_inst uses application/json header, it is correct for a request to ES
    elk_response = annotation_inst.elastic_query(index_templ, elastic_query, time_window, datasource_id)
    # ES responded 'connection error'
    if elk_response is None:
        return None

    try:
        hits = elk_response['responses'][0]['hits']['hits']
    except BaseException as err:
        logger.debug('Elastic request issue: {}'.format(err))
        report_preparation('- ES broken query?')
        return None

    if len(hits) == 0:
        report_preparation()
        if test_mode is False:
            logger.debug(annotation_inst.create_annotation(dash_id_info.id,
                                                           meta_dash.panel_id,
                                                           ref_id(meta_dash.target_json),
                                                           [tag]))
            logger.info("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_dash.title))
        else:
            logger.info("No data state is found on dashboard \"{dashboard}\" panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_dash.title))


def influxdb_flow(time_window, tag, test_mode=False):
    """
    Derives query, initializes request to InfluxDB and creates annotations if data is null
    :param time_window: time_window: time window for search annotations, in s
    :param tag: tag for annotations, type: string
    :param test_mode: test mode
    :return:
    """
    time_filter = 'time >= now() - {timewindow}m'.format(timewindow=str(int(time_window / 60)))
    extract = pretty_search(meta_dash.target_json, 'query')
    try:
        prefix = re.sub(r'\$\S*timeFilter', time_filter, extract[0])
        # GROUP BY replacement
        prefix = re.sub(r'\$\S*interval', '30s', prefix)
    except TypeError as err:
        logger.debug("Error: {err}, can't find query. Check dashboard {d}, panel {p}, query {q}".
                     format(err=err,
                            d=dash_id_info.name,
                            p=meta_dash.title,
                            q=ref_id(meta_dash.target_json)))
        report_preparation('- influxdb broken query?')
        return None
    metric_data = request_inst.influxdb_query(prefix, datasource_db, datasource_id)

    no_data = 0
    for query in request_inst.influx_checker(metric_data):
        if 'NO DATA' in query:
            no_data += 1

    if no_data == len(request_inst.influx_checker(metric_data)):
        report_preparation()
        if test_mode is False:
            logger.debug(annotation_inst.create_annotation(dash_id_info.id,
                                                           meta_dash.panel_id,
                                                           ref_id(meta_dash.target_json),
                                                           [tag]))
            logger.info("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_dash.title))
        else:
            logger.info("No data state is found on dashboard \"{dashboard}\" panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_dash.title))


def relevant_time(title, skip='abs'):
    """
    Try to extract relevant time or skip pointer from title of panel
    :param skip: specifies that script skips checking of a panel
    :param title: title of panel
    :return: time window or None, in second
    """
    # convert relevant time in title if it exists
    pattern = r'\s\((\S*\/)?(\d*[dhms]|daily|hourly|minute|abs|per day|per hour|per min\D*)\)'
    relevant = re.search(pattern, title)

    if relevant:
        if skip in relevant.group():
            return None

        time_string = relevant.group(2)
        if re.search(r'\d+', time_string):
            time_window = int(re.search(r'\d*', time_string).group()) * TIMEPREFIX.get(
                re.search(r'\D', time_string).group())
        else:
            time_window = TIMEPREFIX.get(time_string)
    else:
        time_window = TIMEWINDOW

    if time_window != TIMEWINDOW:
        logger.debug('Timewindow: {t} panel: {p}'.format(t=time_window, p=title))

    return time_window


def report_preparation(broken_query=''):
    """
    Take values of global variables, compose link, append record to report list
    :return:
    """
    link = '{base_url}/{dash_uid}/{dash_name}?orgId=1&fullscreen&panelId={panel_id}'.format(
        base_url=settings.base,
        dash_uid=dash_id_info.uid,
        dash_name=dash_id_info.name,
        panel_id=meta_dash.panel_id)
    dash_rec = "Dashboard: <b>{}</b>".format(dash_id_info.name)
    panel_rec = "panel: <a href=\"{}\"><i>{}</i></a> {}".format(link, meta_dash.title, broken_query)

    if dash_rec in report_struct.keys():
        if panel_rec in report_struct[dash_rec]:
            report_struct[dash_rec][panel_rec].append(ref_id(meta_dash.target_json))
        else:
            report_struct[dash_rec][panel_rec] = [ref_id(meta_dash.target_json)]

    else:
        report_struct[dash_rec] = {panel_rec: [ref_id(meta_dash.target_json)]}


def send_report(report_struct, receivers):
    """
    Send an email as a report
    :param report_struct: dict {'Db name, panel name, link': [list of queries]}
    :param receivers: list of receivers
    :return:
    """

    sender = 'Liberty Global DataOps <dataops@team>'
    body = "<h1>There is no data here: </h1>"

    for dash, panel_queries in report_struct.items():
        body += "<br>{dash}".format(dash=dash)
        for panel, query in panel_queries.items():
            body += "\n<br>{tab}{tab}{tab}{p}, queries: {q}".format(tab='&emsp;', p=panel, q=' '.join(query))
        body += "\n<br>"

    message = MIMEMultipart('alternative')
    message["Subject"] = "Dashboard Grafana Checker report"
    message["From"] = sender
    message["To"] = ', '.join(receivers)

    text = MIMEText(body, "html")
    message.attach(text)
    try:
        smtp_obj = smtplib.SMTP('localhost')
        smtp_obj.sendmail(sender, receivers, message.as_string())
        logger.info("Successfully sent email report")
    except BaseException as err:
        logger.debug("Error: unable to send email report \n {}".format(err))


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
    parser = ArgumentParser()
    parser.add_argument("-d", "--check",
                        nargs='*',
                        dest="checker",
                        default='all',
                        help='list of checking sources: graphite, influxdb, elastic or all (default)')
    parser.add_argument("-c", "--clean",
                        dest='clean',
                        default=0,
                        type=int,
                        help='time delta (in seconds), when cleaner starts to look for old annotations, '
                             '0 as default')
    parser.add_argument("-t", "--tag",
                        dest='tag',
                        default='NO DATA',
                        type=str,
                        help="value of a tag for search/deletion and adding annotations, 'NO DATA' as default")
    parser.add_argument("-r", "--report",
                        dest="report",
                        action='store_true',
                        help='allow to send email reports, False as default')
    parser.add_argument("-i", "--dry-run",
                        dest='dry_run',
                        action='store_true',
                        help='use the tool without active actions, False as default')

    args = parser.parse_args()

    logger = configure_logging(settings.log_level)
    logger.info('-------------------------------------------------')

    if args.dry_run:
        logger.debug("Test mode has been activated")
    else:
        logger.debug("Tool has been run with following parameters:\n"
                     "checking datasource: {datasource}\n"
                     "cleaner time window: {cleaner}\n"
                     "tag: {tag}\n".format(datasource=args.checker,
                                           cleaner=args.clean,
                                           tag=args.tag))

    # create object - instance for work with Grafana
    request_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers_request)
    annotation_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers_annot)

    report_struct = {}
    id_info_list = []
    for dash in settings.dash_list:
        try:
            for dash_title, dash_id, dash_uid in request_inst.get_uid(dash):
                id_info_list.append(Id_dash(dash_title, dash_id, dash_uid))
        except TypeError as err:
            logger.debug("{dash}: {err}".format(dash=dash, err=err))
            continue

    for dash_id_info in id_info_list:
        logger.info('Dashboard \"{name}\" is on checking now'.format(name=dash_id_info.name))

        # current time in ms
        current_timestamp = int(time.time() * 1000)

        annotation_handler(args.clean, dash_id_info.id, args.tag, args.dry_run)

        dash_data = request_inst.get_dashboard(dash_id_info.uid)
        # get dashboard variables
        dashboard_vars = dict()
        for variable in dash_data['templating']['list']:
            dashboard_vars[variable.get('name')] = variable.get('query')

        # main flow: check data and set annotations
        for meta_dash in panel_info(dash_data['panels']):

            timewindow = relevant_time(meta_dash.title)
            if timewindow is None:
                logger.info("Panel \"{panel}\" is uncheckable by notation 'abs'".format(panel=meta_dash.title))
                continue

            # handler of Grafana datasource name
            if 'default' in meta_dash.datasource:
                datasource_info = request_inst.datasource(settings.default_datasource_name)
            else:
                datasource_info = request_inst.datasource(meta_dash.datasource)

            datasource_id = datasource_info['id']
            datasource_url = datasource_info['url']
            datasource_db = datasource_info['database']

            if 'graphite' in datasource_info['type'] and ('graphite' in args.checker or 'all' in args.checker):
                logger.info("Panel \"{panel}\" (query \"{query}\") is checking...".
                            format(panel=meta_dash.title, query=ref_id(meta_dash.target_json)))
                graphite_flow(timewindow, args.tag, args.dry_run)

            if 'elasticsearch' in datasource_info['type'] and ('elastic' in args.checker or 'all' in args.checker):
                logger.info("Panel \"{panel}\" (query \"{query}\") is checking...".
                            format(panel=meta_dash.title, query=ref_id(meta_dash.target_json)))
                elasticsearch_flow(timewindow, args.tag, args.dry_run)

            if 'influxdb' in datasource_info['type'] and ('influxdb' in args.checker or 'all' in args.checker):
                logger.info("Panel \"{panel}\" (query \"{query}\") is checking...".
                            format(panel=meta_dash.title, query=ref_id(meta_dash.target_json)))
                influxdb_flow(timewindow, args.tag, args.dry_run)

    if args.report and report_struct:
        send_report(report_struct, settings.receivers)
