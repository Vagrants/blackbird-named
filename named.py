#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# pylint: disable=C0111,C0301,R0903,C0103,F0401

__VERSION__ = '0.1.1'

try:
    import simplejson as json
except ImportError:
    import json

import subprocess
import xmltodict
import re
import urllib2
import collections

from blackbird.plugins import base

RRSET = [
    'A',     '!A',
    'AAAA',  '!AAAA',
    'DLV',   '!DLV',
    'DS',    '!DS',
    'MX',    '!MX',
    'NS',    'NSEC',
    'CNAME', 'PTR',
    'RRSIG', 'DNSKEY',
    'TXT',   'NXDOMAIN',
]

RDTYPE = [
    'A',         'AAAA',
    'ANY',       'CNAME',
    'DLV',       'DNSKEY',
    'DS',        'MX',
    'NAPTR',     'NS',
    'NSEC',      'NXT',
    'Others',    'PTR',
    'RESERVED0', 'SOA',
    'SPF',       'SRV',
    'SSHFP',     'TXT',
    'X25'
]


class ConcreteJob(base.JobBase):
    """
    This class is Called by "Executor".
    Get bind statistics
    and send to specified zabbix server.
    """

    def __init__(self, options, queue=None, logger=None):
        super(ConcreteJob, self).__init__(options, queue, logger)

    def build_items(self):
        """
        main loop
        """

        # ping item
        self._ping()

        # get statistics from statistics-channels
        self._statistics()

        # get rndc status information
        self._rndc()

    def build_discovery_items(self):
        """
        main loop for lld
        """

        # get xml from statistics-channels
        xml = self._statistics_channles()

        if xml is None:
            return

        try:
            xml_parsed = xmltodict.parse(xml)
        except:
            return

        # discover view name
        self._lld_view_zone(xml_parsed)

    def _enqueue(self, key, value):

        item = NamedItem(
            key=key,
            value=value,
            host=self.options['hostname']
        )
        self.queue.put(item, block=False)
        self.logger.debug(
            'Inserted to queue {key}:{value}'
            ''.format(key=key, value=value)
        )

    def _ping(self):
        """
        send ping item
        """

        self._enqueue('blackbird.named.ping', 1)
        self._enqueue('blackbird.named.version', __VERSION__)

    def _statistics(self):

        # get xml from statistics-channels
        xml = self._statistics_channles()

        if xml is None:
            return

        try:
            xml_parsed = xmltodict.parse(xml)
        except:
            return

        # view information
        self._view_info(xml_parsed)

        # taskmgr information
        self._taskmgr_info(xml_parsed)

        # server information
        self._server_info(xml_parsed)

        # memory information
        self._memory_info(xml_parsed)

    def _statistics_channles(self):

        url = 'http://{0}:{1}'.format(self.options['statistics_host'],
                                      self.options['statistics_port'])
        req = urllib2.Request(url)

        try:
            response = urllib2.urlopen(req)
            return response.read()
        except urllib2.URLError, e:
            self.logger.debug(
                'can not open "{0}", failed to get statistics'
                ''.format(url)
            )
            return None

    def _view_info(self, data):

        _dict = dict()

        root = data['isc']['bind']['statistics']['views']['view']

        for view in root:

            view_name = view['name']
            _dict[view_name] = dict()

            # zone name and serial
            _dict[view_name]['zone'] = dict()
            for zone in view['zones']['zone']:
                zone_serial = zone['serial']
                match = re.match(r'(.+)/(IN|CF)$', zone['name'])
                zone_name = match.group(1) if match else zone['name']
                _dict[view_name]['zone'][zone_name] = zone_serial

            # query
            _dict[view_name]['resstat'] = dict()
            for res in view['resstat']:
                query_name = res['name']
                query_counter = res['counter']
                _dict[view_name]['resstat'][query_name] = query_counter

            # cache
            _dict[view_name]['cache'] = dict()
            # initialize
            for RR in RRSET:
                _dict[view_name]['cache'][RR] = 0
            if 'rrset' in view['cache']:
                for cache in view['cache']['rrset']:
                    cache_name = cache['name']
                    cache_counter = cache['counter']
                    _dict[view_name]['cache'][cache_name] = cache_counter

        for _view in _dict:

            # send zone name and serial
            for _zone in _dict[_view]['zone']:
                item_key = 'named.statistics.zone.serial[{0}]'.format(_zone)
                self._enqueue(item_key, _dict[_view]['zone'][_zone])

            # send resstat
            for _res in _dict[_view]['resstat']:
                item_key = ('named.statistics.resstat[{0},{1}]'
                            ''.format(_view, _res))
                self._enqueue(item_key, _dict[_view]['resstat'][_res])

            # send cache rrset
            for _rr in _dict[_view]['cache']:
                item_key = ('named.statistics.cache[{0},{1}]'
                            ''.format(_view, _rr))
                self._enqueue(item_key, _dict[_view]['cache'][_rr])

    def _taskmgr_info(self, data):

        root = data['isc']['bind']['statistics']['taskmgr']['thread-model']

        self._enqueue(
            'named.statistics.taskmgr[worker-threads]',
            root['worker-threads']
        )
        self._enqueue(
            'named.statistics.taskmgr[tasks-running]',
            root['tasks-running']
        )

    def _server_info(self, data):

        _dict = dict()

        root = data['isc']['bind']['statistics']['server']

        # boot time and current time
        self._enqueue(
            'named.statistics.server[boot-time]',
            root['boot-time']
        )
        self._enqueue(
            'named.statistics.server[current-time]',
            root['current-time']
        )

        # opcode
        _dict['opcode'] = dict()
        # initialize
        for op in ['QUERY', 'NOTIFY', 'UPDATE']:
            _dict['opcode'][op] = 0

        if not root['requests'] is None:
            if isinstance(root['requests']['opcode'], list):
                for _op in root['requests']['opcode']:
                    self.logger.debug(type(_op))
                    opcode_name = _op['name']
                    opcode_counter = _op['countder']
                    _dict['opcode'][opcode_name] = opcode_counter
            else:
                opcode_name = root['requests']['opcode']['name']
                opcode_counter = root['requests']['opcode']['counter']
                _dict['opcode'][opcode_name] = opcode_counter

        # send opcode
        for _opcode in _dict['opcode']:
            item_key = 'named.statistics.server.opcode[{0}]'.format(_opcode)
            self._enqueue(item_key, _dict['opcode'][_opcode])

        # queries-in
        _dict['rdtype'] = dict()
        # initialize
        for RD in RDTYPE:
            _dict['rdtype'][RD] = 0
        if hasattr(root['queries-in'], 'rdtype'):
            if isinstance(root['queries-in']['rdtype'], list):
                for _rd in root['queries-in']['rdtype']:
                    rdtype_name = _rd['name']
                    rdtype_counter = _rd['counter']
                    _dict['rdtype'][rdtype_name] = rdtype_counter
            else:
                rdtype_name = root['queries-in']['rdtype']['name']
                rdtype_counter = root['queries-in']['rdtype']['counter']
                _dict['rdtype'][rdtype_name] = rdtype_counter

        # send queries-in
        for _qi in _dict['rdtype']:
            item_key = 'named.statistics.server.queries-in[{0}]'.format(_qi)
            self._enqueue(item_key, _dict['rdtype'][_qi])

        # nsstat
        for ns in root['nsstat']:
            item_key = 'named.statistics.server.nsstat[{0}]'.format(ns['name'])
            self._enqueue(item_key, ns['counter'])

        # zonestat
        for zs in root['zonestat']:
            item_key = 'named.statistics.server.zonestat[{0}]'.format(zs['name'])
            self._enqueue(item_key, zs['counter'])

        # sockstat
        for ss in root['sockstat']:
            item_key = 'named.statistics.server.sockstat[{0}]'.format(ss['name'])
            self._enqueue(item_key, ss['counter'])

    def _memory_info(self, data):

        _dict = dict()

        root = data['isc']['bind']['statistics']['memory']

        # context inuse
        _dict['context'] = dict()
        for context in root['contexts']['context']:
            context_name = 'res' if re.search(u'^res', context['name']) else context['name']
            if not context_name in _dict['context']:
                _dict['context'][context_name] = 0
            _dict['context'][context_name] += int(context['inuse'])

        # send context inuse
        for _context in _dict['context']:
            item_key = 'named.statistics.memory.inuse[{0}]'.format(_context)
            self._enqueue(item_key, _dict['context'][_context])

        # summary
        for _arr in ['TotalUse', 'InUse', 'BlockSize', 'ContextSize', 'Lost']:
            item_key = 'named.statistics.memory.summary[{0}]'.format(_arr)
            self._enqueue(item_key, root['summary'][_arr])

    def _lld_view_zone(self, data):

        root = data['isc']['bind']['statistics']['views']['view']

        for view in root:

            item = base.DiscoveryItem(
                key='named.view.LLD',
                value=[
                    {'{#VIEW_NAME}': views['name']} for views in root
                ],
                host=self.options['hostname']
            )
            self.queue.put(item, block=False)

            for zone in view['zones']['zone']:
                match = re.match(r'(.+)/(IN|CF)$', zone['name'])
                zone_name = match.group(1) if match else zone['name']

                item = base.DiscoveryItem(
                    key='named.zone.LLD',
                    value=[{'{#ZONE_NAME}': zone_name}],
                    host=self.options['hostname']
                )
                self.queue.put(item, block=False)

    def _rndc(self):
        """
        # rndc status
        version: 9.8
        CPUs found: 2
        worker threads: 2
        number of zones: 1
        debug level: 0
        xfers running: 0
        xfers deferred: 0
        soa queries in progress: 0
        query logging is OFF
        recursive clients: 0/0/1000
        tcp clients: 0/100
        server is up and running
        """

        rndc = self.options['rndc_path']

        # nothing to do
        if rndc is None:
            return

        # rndc status
        cmd = [rndc, 'status']

        try:
            output = subprocess.Popen(cmd,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT,
                                     )

            for _line in output.stdout.readlines():
                line = _line.rstrip()

                # something wrong
                if re.search(r'error', line):
                    self.logger.error('rndc exec error [{0}]'.format(line))
                    return

                try:
                    _key, _value = line.split(':')
                    value = _value.lstrip()
                    if _key == 'recursive clients':
                        used, soft, max = value.split('/')
                        self._enqueue('named.rndc[recursive_clients_used]', used)
                        self._enqueue('named.rndc[recursive_clients_soft]', soft)
                        self._enqueue('named.rndc[recursive_clients_max]', max)
                    elif _key == 'tcp clients':
                        tused, tmax = value.split('/')
                        self._enqueue('named.rndc[tcp_clients_used]', tused)
                        self._enqueue('named.rndc[tcp_clients_max]', tmax)
                    else:
                        self._enqueue(
                            'named.rndc[{0}]'.format(_key.replace(' ', '_')),
                            value
                        )

                except ValueError:
                    # query logging
                    _m = re.match(r'^query logging is (\w+)', line)
                    if _m:
                        self._enqueue('named.rndc[query_logging]', _m.group(1))
                        continue

                    # server is up and running
                    _m = re.match(r'^server is (.*)', line)
                    if _m:
                        self._enqueue('named.rndc[server_is]', _m.group(1))
                        continue

        except OSError, IOError:
            self.logger.error(
                'can not exec "{0}"'.format(' '.join(cmd))
            )

class NamedItem(base.ItemBase):
    """
    Enqued item.
    """

    def __init__(self, key, value, host):
        super(NamedItem, self).__init__(key, value, host)

        self._data = {}
        self._generate()

    @property
    def data(self):
        return self._data

    def _generate(self):
        self._data['key'] = self.key
        self._data['value'] = self.value
        self._data['host'] = self.host
        self._data['clock'] = self.clock


class Validator(base.ValidatorBase):
    """
    Validate configuration.
    """

    def __init__(self):
        self.__spec = None

    @property
    def spec(self):
        """
        "user" and "password" in spec are
        for BASIC and Digest authentication.
        """
        self.__spec = (
            "[{0}]".format(__name__),
            "rndc_path=string(default=None)",
            "statistics_host=string(default='127.0.0.1')",
            "statistics_port=integer(0, 65535, default=5353)",
            "hostname=string(default={0})".format(self.detect_hostname()),
        )
        return self.__spec
