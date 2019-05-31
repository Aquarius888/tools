# TODO: search through folders, tags
# TODO: variable's handler in query (influx)
# TODO: mark query as uncheckable by underscore after the alias

"""
The tool goes through dashboards (panel's type 'graph') and looks for gaps in data,
in this case, adds an annotation on a panel and/or composes a report and send it to email.
"""
from argparse import ArgumentParser
import asyncio
import aiohttp

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
        self.proxy = proxy
        # self.headers = headers
        self.session = aiohttp.ClientSession(headers=headers)

    async def close_session(self):
        await self.session.close()

    async def get_uid(self, name_dash):
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
        response = await self.session.get(composed_url)

        try:
            assert await response.json() != []
            for db in await response.json():
                id_uid.append((db['title'], db['id'], db['uid']))
        except AssertionError:
            logger.debug("Dashboard \"{}\" doesn't exist".format(name_dash))
            return None

        return id_uid

    async def get_dashboard(self, uid):
        """
        Get dashboard's data by uid
        :param uid: dashboard uid
        :return: json
        """
        composed_url = '{base}/dashboards/uid/{uid}'.format(
            base=self.url_api,
            uid=uid)
        response = await self.session.get(composed_url)
        return await response.json()

    async def get_folders(self, limit=20):
        """
        Get list of {id, uid, title} for all (limit) folders
        :param limit: limit for request
        :return: json
        """
        composed_url = '{base}/folders?limit={limit}'.format(
            base=self.url_api,
            limit=limit
        )
        response = await self.session.get(composed_url)
        return await response.json()

    async def search_in_folder(self, folder_id, dash_query):
        """
        Get json with at least id, uid, title of found dashboards
        :param folder_id:
        :param dash_query:
        :return: json
        """
        composed_url = '{base}/search?folderIds={folder_id}&query={dash_query}&starred=false'.format(
            base=self.url_api,
            folder_id=folder_id,
            dash_query=dash_query
        )
        response = await self.session.get(composed_url)
        return await response.json()

    async def datasource(self, ds_name):
        """
        Get a data source info by name
        :param ds_name: name of data source
        :return: json with id, name, url and etc of data source
        """
        composed_url = '{base}/datasources/name/{name}'.format(
            base=self.url_api,
            name=ds_name
        )
        response = await self.session.get(composed_url)
        return await response.json()

    async def create_annotation(self, dash_id, panel_id, ref_id, tag):
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
                   "text": "Query {} \n Annotation's been added automatically by dashboard-checker".format(ref_id)}
        response = await self.session.post(composed_url, data=json.dumps(payload).encode('utf-8'))
        return await response.text()

    async def find_annotation(self, gte, lte, dash_id, tag, limit=100):
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
        response = await self.session.get(composed_url)
        return await response.json()

    async def delete_annotation(self, annot_id):
        """
        Removes old annotation
        :param annot_id: annotation id
        :return:
        """
        composed_url = '{base}/annotations/{id}'.format(
            base=self.url_api,
            id=annot_id)
        response = await self.session.delete(composed_url)
        return await response.json()

    async def graphite_query(self, prefix, ds_id, time_window):
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
        return await self._get_proxy_call(ds_id, 'render', request)

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

    async def elastic_query(self, index_tmpl, query, time_window, ds_id):
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

        return await self._get_proxy_call(ds_id, '_msearch', data)

    async def influxdb_query(self, prefix, database, ds_id):
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

        return await self._get_proxy_call(ds_id, 'query', request)

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

    async def _get_proxy_call(self, ds_id, query, request):
        """
        Make Grafana API proxy call
        :param ds_id: id of datasource
        :param query: special word
        :param request: request
        :return: response in json
        """
        response = await self.session.post('{base}/datasources/proxy/{datasource_id}/{query}'.format(
            base=self.url_api,
            datasource_id=ds_id,
            query=query),
            data=request)

        return await response.json()


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


async def annotation_handler(time_window, dash_id, tag, test_mode=False):
    """
    Handles Grafana's annotations, looks for annotations on dashboard according to its id and tag and deletes it
    :param time_window: time window for search annotations, in s
    :param dash_id: id of dashboard
    :param tag: tag of annotations
    :param test_mode: test mode
    :return:
    """
    annot_list = await request_inst.find_annotation(
        current_timestamp - time_window * 1000, current_timestamp, dash_id, tag)
    annotation_list_id = [annot.get('id') for annot in annot_list]
    for annot_id in annotation_list_id:
        if test_mode is False:
            await request_inst.delete_annotation(annot_id)
            logger.info("Annotation with id: {annot} has been deleted".format(annot=annot_id))
        else:
            logger.info("Annotation with id: {annot} is found on a dashboard id: {dash}".format(annot=annot_id,
                                                                                                dash=dash_id))


async def graphite_flow(time_window, tag, meta_info, dash_id_info, dashboard_vars, datasource_id, test_mode=False):
    """
    Derive graphite metric's path, get list of metric's data for specified time window, initialize request
    create annotations if data is null
    :param time_window: time window for search annotations, in s
    :param tag: tag for annotations, type: string
    :param meta_info:
    :param dash_id_info:
    :param dashboard_vars:
    :param datasource_id:
    :param test_mode: test mode
    :return:
    """
    no_data = 0
    extract = pretty_search(meta_info.target_json, 'targetFull')
    if extract is None or []:
        extract = pretty_search(meta_info.target_json, 'target')

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
                                 meta_info.title,
                                 ref_id(meta_info.target_json)))
            report_preparation(dash_id_info, meta_info, '- graphite broken query?')
            return None

    metric_data = await request_inst.graphite_query(prefix, datasource_id, time_window)
    checked_list = request_inst.graphite_checker(metric_data)

    if not metric_data:
        logger.debug("Check graphite query, seems like it is not ready. Dash: {d}, panel: {p}, query: {q}".
                     format(d=dash_id_info.name,
                            p=meta_info.title,
                            q=ref_id(meta_info.target_json)))

    for query in checked_list:
        if 'NO DATA' in query:
            no_data += 1

    if no_data == len(checked_list):
        report_preparation(dash_id_info, meta_info)
        if test_mode is False:
            logger.debug(await annotation_inst.create_annotation(dash_id_info.id,
                                                                 meta_info.panel_id,
                                                                 ref_id(meta_info.target_json),
                                                                 [tag]))
            logger.info("Annotation has been added on dashboard \"{dashboard}\" panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_info.title))
        else:
            # Test mode is activated
            logger.info("No data state is found on dashboard \"{dashboard}\" panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_info.title))


async def elasticsearch_flow(time_window, tag, datasource_db, datasource_id, meta_info, dash_id_info, test_mode=False):
    """
    Derive index and format it to template (index-*), initialize request,
    create annotations if data is null
    :param time_window: time window for search annotations, in s
    :param tag: tag for annotations, type: string
    :param datasource_db:
    :param datasource_id
    :param meta_info:
    :param dash_id_info:
    :param test_mode: test mode
    :return:
    """
    index_templ = datasource_db
    if re.search(r'\[(\S+)\]', datasource_db):
        index_templ = re.search(r'\[(\S+)\]', datasource_db).group(1) + '*'

    elastic_query = pretty_search(meta_info.target_json, 'query')[0]

    if '\"' in elastic_query:
        elastic_query = elastic_query.replace('\"', '\\"')

    # annotation_inst uses application/json header, it is correct for a request to ES
    elk_response = await annotation_inst.elastic_query(index_templ, elastic_query, time_window, datasource_id)
    # ES responded 'connection error' ?
    if elk_response is None:
        return None

    try:
        hits = elk_response['responses'][0]['hits']['hits']
    except KeyError:
        logger.debug('Bad response!? {}'.format(elastic_query))
        report_preparation(dash_id_info, meta_info, '- ES broken query?')
        return None
    except BaseException as err:
        logger.debug('Elastic request issue: {}'.format(err))
        return None

    if len(hits) == 0:
        report_preparation(dash_id_info, meta_info)
        if test_mode is False:
            logger.debug(await annotation_inst.create_annotation(dash_id_info.id,
                                                                 meta_info.panel_id,
                                                                 ref_id(meta_info.target_json),
                                                                 [tag]))
            logger.info("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_info.title))
        else:
            logger.info("No data state is found on dashboard \"{dashboard}\" panel \"{panel}\" query \"{query}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_info.title,
                               query=ref_id(meta_info.target_json)))


async def influxdb_flow(time_window, tag, dash_id_info, meta_info, datasource_db, datasource_id, test_mode=False):
    """
    Derives query, initializes request to InfluxDB and creates annotations if data is null
    :param time_window: time_window: time window for search annotations, in s
    :param tag: tag for annotations, type: string
    :param dash_id_info:
    :param meta_info:
    :param datasource_db:
    :param datasource_id:
    :param test_mode: test mode
    :return:
    """
    time_filter = 'time >= now() - {timewindow}m'.format(timewindow=str(int(time_window / 60)))
    extract = pretty_search(meta_info.target_json, 'query')
    try:
        prefix = re.sub(r'\$\S*timeFilter', time_filter, extract[0])
        # GROUP BY replacement
        prefix = re.sub(r'\$\S*interval', '30s', prefix)
    except TypeError as err:
        logger.debug("Error: {err}, can't find query. Check dashboard {d}, panel {p}, query {q}".
                     format(err=err,
                            d=dash_id_info.name,
                            p=meta_info.title,
                            q=ref_id(meta_info.target_json)))
        report_preparation(dash_id_info, meta_info, '- influxdb broken query?')
        return None
    metric_data = await request_inst.influxdb_query(prefix, datasource_db, datasource_id)

    no_data = 0
    influx_check = request_inst.influx_checker(metric_data)
    for query in influx_check:
        if 'NO DATA' in query:
            no_data += 1

    if no_data == len(influx_check):
        report_preparation(dash_id_info, meta_info)
        if test_mode is False:
            logger.debug(await annotation_inst.create_annotation(dash_id_info.id,
                                                                 meta_info.panel_id,
                                                                 ref_id(meta_info.target_json),
                                                                 [tag]))
            logger.info("Annotation has been added on dashboard \"{dashboard}\" on panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_info.title))
        else:
            logger.info("No data state is found on dashboard \"{dashboard}\" panel \"{panel}\"".
                        format(dashboard=dash_id_info.name,
                               panel=meta_info.title))


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


def report_preparation(dash_id_info, meta_info, broken_query=''):
    """
    Take values of global variables, compose link, append record to report list
    :return:
    """
    link = '{base_url}/{dash_uid}/{dash_name}?orgId=1&fullscreen&panelId={panel_id}'.format(
        base_url=settings.base,
        dash_uid=dash_id_info.uid,
        dash_name=dash_id_info.name,
        panel_id=meta_info.panel_id)
    dash_rec = "Dashboard: <b>{}</b>".format(dash_id_info.name)
    panel_rec = "panel: <a href=\"{}\"><i>{}</i></a> {}".format(link, meta_info.title, broken_query)

    if dash_rec in report_struct.keys():
        if panel_rec in report_struct[dash_rec]:
            report_struct[dash_rec][panel_rec].append(ref_id(meta_info.target_json))
        else:
            report_struct[dash_rec][panel_rec] = [ref_id(meta_info.target_json)]

    else:
        report_struct[dash_rec] = {panel_rec: [ref_id(meta_info.target_json)]}


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


async def get_dash_info_from_folder(folder, query=''):
    json_folder = await request_inst.get_folders()

    for directory in json_folder:
        if folder in directory['title']:
            folder_id = directory['id']

    json_folder_dash = await request_inst.search_in_folder(folder_id, query)
    for dash in json_folder_dash:
        id_info_list.append(Id_dash(dash['title'], dash['id'], dash['uid']))


async def get_dash_info(dash):
    try:
        for dash_title, dash_id, dash_uid in await request_inst.get_uid(dash):
            id_info_list.append(Id_dash(dash_title, dash_id, dash_uid))
    except TypeError:
        return None


async def exec_dash_info():
    id_info_tasks = []
    for dash in settings.dash_list:
        id_info_tasks.append(asyncio.ensure_future(get_dash_info(dash)))

    await asyncio.wait(id_info_tasks)


async def annotation():
    annot_tasks = []
    for dash_id_info in id_info_list:
        annot_tasks.append(asyncio.ensure_future(
            annotation_handler(args.clean, dash_id_info.id, args.tag, args.dry_run)))

    try:
        await asyncio.wait(annot_tasks)
    except ValueError as err:
        logger.debug("There is no one task in annotation flow for the dashboard... {}".format(err))


async def main():
    elastic_request = 0
    graphite_request = 0
    influx_request = 0
    for dash_id_info in id_info_list:
        logger.info('Dashboard \"{name}\" is on checking now'.format(name=dash_id_info.name))
        dash_tasks = []
        dash_data = await request_inst.get_dashboard(dash_id_info.uid)
        db_data = dash_data['dashboard']

        dashboard_vars = dict()
        for variable in db_data['templating']['list']:
            dashboard_vars[variable.get('name')] = variable.get('query')

        for meta_dash in panel_info(db_data['panels']):

            timewindow = relevant_time(meta_dash.title)
            if timewindow is None:
                logger.info("Panel \"{panel}\" is uncheckable by notation 'abs'".format(panel=meta_dash.title))
                continue

            # handler of Grafana datasource name
            if 'default' in meta_dash.datasource:
                datasource_info = await request_inst.datasource(settings.default_datasource_name)
            else:
                datasource_info = await request_inst.datasource(meta_dash.datasource)

            datasource_id = datasource_info['id']
            datasource_db = datasource_info['database']

            if 'graphite' in datasource_info['type'] and ('graphite' in args.checker or 'all' in args.checker):
                graphite_request += 1
                logger.info("Panel \"{panel}\" (query \"{query}\") is checking...".
                            format(panel=meta_dash.title, query=ref_id(meta_dash.target_json)))
                dash_tasks.append(asyncio.ensure_future(graphite_flow(timewindow, args.tag, meta_dash, dash_id_info,
                                                                      dashboard_vars, datasource_id, args.dry_run)))

            if 'elasticsearch' in datasource_info['type'] and ('elastic' in args.checker or 'all' in args.checker):
                elastic_request += 1
                logger.info("Panel \"{panel}\" (query \"{query}\") is checking...".
                            format(panel=meta_dash.title, query=ref_id(meta_dash.target_json)))
                dash_tasks.append(asyncio.ensure_future(elasticsearch_flow(timewindow, args.tag, datasource_db,
                                                                           datasource_id, meta_dash, dash_id_info,
                                                                           args.dry_run)))

            if 'influxdb' in datasource_info['type'] and ('influxdb' in args.checker or 'all' in args.checker):
                influx_request += 1
                logger.info("Panel \"{panel}\" (query \"{query}\") is checking...".
                            format(panel=meta_dash.title, query=ref_id(meta_dash.target_json)))
                dash_tasks.append(asyncio.ensure_future(influxdb_flow(timewindow, args.tag, dash_id_info, meta_dash,
                                                                      datasource_db, datasource_id, args.dry_run)))

        try:
            await asyncio.wait(dash_tasks)
        except ValueError as err:
            logger.debug("There is no one task in main flow for the dashboard... {}".format(err))

    print("Executed: graphite - {}, ES - {}, InfluxDB - {}".format(graphite_request,
                                                                   elastic_request, influx_request))


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
    parser.add_argument("-f", "--folder",
                        dest='folder',
                        type=str,
                        help="name of grafana folder for checking dashboards")
    parser.add_argument("-q", "--query-folder",
                        dest='dash_query',
                        type=str,
                        help="name or part of name of dashboard(s) for checking, REQUIRES -f key filled")
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
        logger.debug("Silent mode has been activated")
    else:
        logger.debug("Tool has been run with following parameters:\n"
                     "checking datasource: {datasource}\n"
                     "cleaner time window: {cleaner}\n"
                     "tag: {tag}\n".format(datasource=args.checker,
                                           cleaner=args.clean,
                                           tag=args.tag))

    request_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers_request)
    annotation_inst = GrafanaMaker(settings.url_api, settings.proxy, settings.headers_annot)

    report_struct = {}
    id_info_list = []

    ioloop = asyncio.get_event_loop()

    if args.folder:
        ioloop.run_until_complete(get_dash_info_from_folder(args.folder, args.dash_query))
    else:
        ioloop.run_until_complete(exec_dash_info())

    # current time in ms
    current_timestamp = int(time.time() * 1000)
    ioloop.run_until_complete(annotation())

    ioloop.run_until_complete(main())

    ioloop.run_until_complete(annotation_inst.close_session())
    ioloop.run_until_complete(request_inst.close_session())
    ioloop.close()

    if args.report and report_struct:
        send_report(report_struct, settings.receivers)
