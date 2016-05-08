#!/usr/bin/python

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This is the main module of the nmeta2 suite
running on top of the Ryu SDN controller to provide network identity
and flow (traffic classification) metadata.
.
It supports OpenFlow v1.3 switches and v0.2.x Data Path Auxiliary Engines
(DPAE)
.
Version 2.x Toulouse Code
.
Do not use this code for production deployments - it is proof
of concept code and carries no warrantee whatsoever.
.
You have been warned.
"""

#*** Logging Imports:
import logging
#import coloredlogs

#*** General Imports:
import sys
import time

#*** mongodb Database Import:
from pymongo import MongoClient

#*** Ryu Imports:
from ryu import utils
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import tcp

#*** Required for api module context:
from ryu.app.wsgi import WSGIApplication

#*** nmeta imports:
import config
import switch_abstraction
import api
import main_policy
import of_error_decode

#*** JSON imports:
import json
from json import JSONEncoder

#*** Universal Unique Identifier:
from uuid import UUID

class Nmeta(app_manager.RyuApp):
    """
    This is the main class of nmeta2 and is run by Ryu
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    #*** Used to call api module:
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(Nmeta, self).__init__(*args, **kwargs)

        #*** Version number for compatibility checks:
        self.version = '0.3.0'

        #*** Instantiate config class which imports configuration file
        #*** config.yaml and provides access to keys/values:
        self.config = config.Config()

        #*** Get logging config values from config class:
        _logging_level_s = self.config.get_value \
                                    ('nmeta_logging_level_s')
        _logging_level_c = self.config.get_value \
                                    ('nmeta_logging_level_c')
        _syslog_enabled = self.config.get_value('syslog_enabled')
        _loghost = self.config.get_value('loghost')
        _logport = self.config.get_value('logport')
        _logfacility = self.config.get_value('logfacility')
        _syslog_format = self.config.get_value('syslog_format')
        _console_log_enabled = self.config.get_value('console_log_enabled')
        _coloredlogs_enabled = self.config.get_value('coloredlogs_enabled')
        _console_format = self.config.get_value('console_format')
        #*** Set up Logging:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        #*** Syslog:
        if _syslog_enabled:
            #*** Log to syslog on host specified in config.yaml:
            self.syslog_handler = logging.handlers.SysLogHandler(address=(
                                                _loghost, _logport),
                                                facility=_logfacility)
            syslog_formatter = logging.Formatter(_syslog_format)
            self.syslog_handler.setFormatter(syslog_formatter)
            self.syslog_handler.setLevel(_logging_level_s)
            #*** Add syslog log handler to logger:
            self.logger.addHandler(self.syslog_handler)
        #*** Console logging:
        if _console_log_enabled:
            #*** Log to the console:
            self.console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(_console_format)
            self.console_handler.setFormatter(console_formatter)
            self.console_handler.setLevel(_logging_level_c)
            #*** Add console log handler to logger:
            self.logger.addHandler(self.console_handler)

        #*** Set a variable to indicate if either or both levels are
        #***  at debug:
        if _logging_level_s == 'DEBUG' or _logging_level_c == 'DEBUG':
            self.debug_on = True
        else:
            self.debug_on = False
        #*** Set up variables:
        #*** Get max bytes of new flow packets to send to controller from
        #*** config file:
        self.miss_send_len = self.config.get_value("miss_send_len")
        if self.miss_send_len < 1500:
            self.logger.info("Be aware that setting "
                             "miss_send_len to less than a full size packet "
                             "may result in errors due to truncation. "
                             "Configured value is %s bytes",
                             self.miss_send_len)

        #*** Load the Flow Table ID numbers:
        self.ft_iig = self.config.get_value("ft_iig")
        self.ft_iim = self.config.get_value("ft_iim")
        self.ft_tc = self.config.get_value("ft_tc")
        self.ft_tt = self.config.get_value("ft_tt")
        self.ft_fwd = self.config.get_value("ft_fwd")

        #*** Context Configuration:
        self.context_default = self.config.get_value("context_default")

        #*** DPAE Registration Parameters:
        self.dpae2ctrl_mac = self.config.get_value("dpae2ctrl_mac")
        self.ctrl2dpae_mac = self.config.get_value("ctrl2dpae_mac")
        self.dpae_ethertype = self.config.get_value("dpae_ethertype")

        #*** Tell switch how to handle fragments (see OpenFlow spec):
        self.ofpc_frag = self.config.get_value("ofpc_frag")

        #*** Update JSON to support UUID encoding:
        JSONEncoder_olddefault = JSONEncoder.default
        def JSONEncoder_newdefault(self, o):
            if isinstance(o, UUID):
                return str(o)
            return JSONEncoder_olddefault(self, o)
        JSONEncoder.default = JSONEncoder_newdefault

        #*** Instantiate Module Classes:
        self.switches = switch_abstraction.Switches(self, self.config)
        wsgi = kwargs['wsgi']
        self.api = api.Api(self, self.config, wsgi)
        self.main_policy = main_policy.MainPolicy(self.config)

        #*** Start mongodb:
        self.logger.info("Connecting to mongodb database...")
        self.mongo_addr = self.config.get_value("mongo_addr")
        self.mongo_port = self.config.get_value("mongo_port")
        mongo_client = MongoClient(self.mongo_addr, self.mongo_port)

        #*** Connect to specific databases and collections in mongodb:
        #*** ID Service database:
        db_svc = mongo_client.idsvc_database
        self.dbidsvc = db_svc.idsvc

        #*** ID Node database:
        db_node = mongo_client.idnode_database
        self.dbidnode = db_svc.idnode

        #*** ID IP database:
        db_ip = mongo_client.idip_database
        self.dbidip = db_svc.idip

        #*** ID MAC database (with a connection test var):
        db_mac = mongo_client.mac_database
        self.dbidmac = db_mac.idmac
        dbtest = db_mac.cxntest

        #*** DPAE database:
        db_dpae = mongo_client.dpae_database
        self.dbdpae = db_dpae.dpae

        #*** Test a Database Connection:
        try:
            dbtest.delete_many({})
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.critical("Fatal. Mongodb connection failed. "
                   "Exception %s, %s, %s. Check that database"
                    " is running and nmeta config file has correct mongodb "
                    "connection parameters",
                    exc_type, exc_value, exc_traceback)
            sys.exit()
        test_data = {"testing": "1,2,3"}
        test_id = dbtest.insert_one(test_data).inserted_id
        result = dbtest.find(test_data).count()
        if result == 1:
            self.logger.info("Success! Connected to mongodb database")
        else:
            self.logger.critical("Fatal. Mongodb test failed"
              "database addr mongo_addr=%s mongo_port=%s. Check that database"
              " is running and nmeta config file has correct mongodb "
              "connection parameters", self.mongo_addr, self.mongo_port)
            sys.exit()

        #*** ID Service database - delete all previous entries:
        result = self.dbidsvc.delete_many({})
        self.logger.info("Initialising ID Service database, Deleted %s "
                "previous entries from dbidsvc", result.deleted_count)

        #*** ID Node database - delete all previous entries:
        result = self.dbidnode.delete_many({})
        self.logger.info("Initialising ID Node database, Deleted %s previous "
                "entries from dbidnode", result.deleted_count)

        #*** ID IP database - delete all previous entries:
        result = self.dbidip.delete_many({})
        self.logger.info("Initialising ID IP database, Deleted %s previous "
                "entries from dbidip", result.deleted_count)

        #*** ID MAC database - delete all previous entries:
        result = self.dbidmac.delete_many({})
        self.logger.info("Initialising ID MAC database, Deleted %s previous "
                "entries from dbidmac", result.deleted_count)

        #*** DPAE database - delete all previous entries:
        result = self.dbdpae.delete_many({})
        self.logger.info("Initialising DPAE database, Deleted %s previous "
                "entries from dbdpae", result.deleted_count)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connection_handler(self, ev):
        """
        A switch has connected to the SDN controller.
        We need to do some tasks to set the switch up properly:
         - Instantiate a class to represent the switch and flow tables
         - Delete all existing flow entries
         - Set config for fragment handling and table miss packet length
         - Set up initial flow entries in flow tables
         - Install non-DPAE TC flows from optimised policy to switch
         - Request the switch send us its description
        Supported OpenFlow versions is controlled by the OFP_VERSIONS
        constant set in class base.
        """
        datapath = ev.msg.datapath
        self.logger.info("In switch_connection_handler dpid=%s", datapath.id)

        #*** Add switch to our class abstraction:
        self.switches.add(datapath)
        switch = self.switches[datapath.id]

        #*** Delete all existing flows from the switch:
        switch.flowtables.delete_all_flows()

        #*** Set the configuration on the switch:
        switch.set_switch_config(self.ofpc_frag, self.miss_send_len)

        #*** Set up switch flow table basics:
        switch.flowtables.add_fe_iig_broadcast()
        switch.flowtables.add_fe_iig_miss()
        switch.flowtables.add_fe_iim_miss()
        switch.flowtables.add_fe_tcf_accepts()
        switch.flowtables.add_fe_tcf_miss()
        switch.flowtables.add_fe_tc_miss()
        switch.flowtables.add_fe_tt_miss()
        switch.flowtables.add_fe_fwd_miss()

        #*** Set flow entry for DPAE join packets:
        switch.flowtables.add_fe_iig_dpae_join()

        #*** Install non-DPAE static TC flows from optimised policy to switch:
        switch.flowtables.add_fe_tc_static \
                              (self.main_policy.optimised_rules.get_rules())

        #*** Request the switch send us it's description:
        switch.request_switch_desc()


    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        """
        Receive a reply from a switch to a description
        statistics request
        """
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.logger.info('event=DescStats Switch dpid=%s is mfr_desc="%s" '
                      'hw_desc="%s" sw_desc="%s" serial_num="%s" dp_desc="%s"',
                      dpid, body.mfr_desc, body.hw_desc, body.sw_desc,
                      body.serial_num, body.dp_desc)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        A switch has sent an event to us because it has removed
        a flow from a flow table
        """
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        self.logger.debug('Flow removed msg '
                              'cookie=%d priority=%d reason=%s table_id=%d '
                              'duration_sec=%d '
                              'idle_timeout=%d hard_timeout=%d '
                              'packets=%d bytes=%d match=%s',
                              msg.cookie, msg.priority, reason, msg.table_id,
                              msg.duration_sec,
                              msg.idle_timeout, msg.hard_timeout,
                              msg.packet_count, msg.byte_count, msg.match)

        if msg.table_id == self.ft_iim:
            #*** Flow entries that age out of IIM table need to remove entry
            #***  from FWD table for that MAC:
            self.logger.debug("FE removed from IIM table. Will delete "
                                    "equivalent forwarding FE")
            #match=OFPMatch(oxm_fields={'eth_src': '08:00:27:c8:db:91', 'in_port': 2})
            #NEED TO REFORMAT, TAKE MAC FROM IT AND PUT INTO FWD MATCH...



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        A switch has sent us a Packet In event
        """
        msg = ev.msg
        datapath = msg.datapath
        switch = self.switches[datapath.id]
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        #*** TBD, deal with context:
        context = self.context_default

        #*** Extra debug if syslog or console logging set to DEBUG:
        if self.debug_on:
            self._packet_in_debug(ev, in_port)

        #*** Is it a DPAE Join request? If so, call function to handle it:
        if eth.src == self.ctrl2dpae_mac and eth.dst == self.dpae2ctrl_mac:
            self.dpae_join(pkt, datapath, in_port)

        self.logger.debug("Learned mac=%s dpid=%s port=%s",
                               eth.src, datapath.id, in_port)

        #*** Add to MAC/port pair to switch MAC table:
        switch.mactable.add(eth.src, in_port, context)

        #*** Add source MAC / in port to Identity Indicator (MAC) table so
        #***  that we don't get further packet in events for this combo:
        switch.flowtables.add_fe_iim_macport_src(in_port, eth.src)

        #*** Add source MAC / in port to Forwarding table as destinations so
        #***  that we don't flood them:
        switch.flowtables.add_fe_fwd_macport_dst(in_port, eth.src)

        #*** Don't do a packet out, as it continued through the pipeline...


    @set_ev_cls(ofp_event.EventOFPErrorMsg,
            [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        """
        A switch has sent us an error event
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        self.logger.error('event=OFPErrorMsg_received: dpid=%s '
                      'type=%s code=%s message=%s',
                      dpid, msg.type, msg.code, utils.hex_array(msg.data))
        #*** Log human-friendly decodes for the error type and code:
        type1, type2, code1, code2 = of_error_decode.decode(msg.type, msg.code)
        self.logger.error('error_type=%s %s error_code=%s %s', type1, type2,
                                code1, code2)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
        Switch Port Status event
        """
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)

    def tc_start(self, datapath, dpae_port):
        """
        Add a Flow Entry to switch to clone selected packets to a
        DPAE so that it can perform Traffic Classification analysis
        on them
        """
        self.logger.info("Starting TC to DPAE on datapath=%s, dpae_port=%s",
                            datapath.id, dpae_port)
        switch = self.switches[datapath.id]
        #*** Check if Active or Passive TC Mode:
        mode = self.main_policy.tc_policies.mode

        #*** Set up group table to send to DPAE:
        # NEEDS OVS 2.1 OR HIGHER SO COMMENTED OUT FOR THE MOMENT
        # ALSO NEEDS CODE THAT CAN CATER FOR MULTIPLE DPAE
        #switch.flowtables.add_group_dpae(out_port)

        if self.main_policy.identity.lldp:
            #*** Install FEs to send LLDP Identity indicators to DPAE:
            switch.flowtables.add_fe_iig_lldp(dpae_port)

        if self.main_policy.identity.dhcp:
            #*** Install FEs to send DHCP Identity indicators to DPAE:
            switch.flowtables.add_fe_iig_dhcp(dpae_port)

        if self.main_policy.identity.dns:
            #*** Install FEs to send DNS Identity indicators to DPAE:
            switch.flowtables.add_fe_iig_dns(dpae_port)

        if mode == 'active':
            #*** Install FE to so packets returning from DPAE in active mode
            #*** bypass learning tables and go straight to treatment:
            switch.flowtables.add_fe_iig_dpae_active_bypass(dpae_port)

        #*** Add any general TC flows to send to DPAE if required by policy
        #*** (i.e. statistical or payload):
        switch.flowtables.add_fe_tc_dpae(
                        self.main_policy.optimised_rules.get_rules(),
                        dpae_port, mode)

        self.logger.info("TC started to DPAE on datapath=%s, dpae_port=%s",
                            datapath.id, dpae_port)
        _results = {"status": "tc_started",
                        "mode": mode}
        return _results

    def dpae_join(self, pkt, datapath, in_port):
        """
        A DPAE may have sent us a join discovery packet (Phase 2)
        Check the packet payload to see if it is valid
        """
        _payload = str(pkt.protocols[-1])
        self.logger.info("Phase 2 DPAE discovery packet received from dpid=%s "
                                "port=%s payload=%s",
                                datapath.id, in_port, _payload)
        #*** Try decode of payload as JSON:
        try:
            dpae_discover = json.loads(_payload)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Phase 2 DPAE API Create exception while "
                            "decoding JSON body=%s Exception %s, %s, %s",
                            _payload, exc_type, exc_value, exc_traceback)
            return 0
        #*** Check to see if JSON has a uuid_controller key:
        if 'uuid_controller' in dpae_discover:
            uuid_controller = dpae_discover['uuid_controller']
        else:
            self.logger.debug("No uuid_controller field in discovery "
                                    "packet so ignoring...")
            return 0
        #*** Check to see if JSON has a hostname_dpae key:
        if 'hostname_dpae' in dpae_discover:
            hostname_dpae = dpae_discover['hostname_dpae']
        else:
            self.logger.debug("No hostname_dpae field in discovery "
                                    "packet so ignoring...")
            return 0
        #*** Check to see if JSON has a if_name key:
        if 'if_name' in dpae_discover:
            if_name = dpae_discover['if_name']
        else:
            self.logger.debug("No if_name field in discovery "
                                    "packet so ignoring...")
            return 0
        #*** Check to see if JSON has a uuid_dpae key:
        if 'uuid_dpae' in dpae_discover:
            uuid_dpae = dpae_discover['uuid_dpae']
        else:
            self.logger.debug("No uuid_dpae field in discovery "
                                    "packet so ignoring...")
            return 0
        #*** Look the key up in the database:
        db_result = self.dbdpae.find_one({'_id': str(uuid_controller)})
        if db_result:
            #*** Check all fields match:
            if not hostname_dpae == str(db_result[u'hostname_dpae']):
                self.logger.error("Phase 2 hostname_dpae mismatch")
                return 0
            if not if_name == str(db_result[u'if_name']):
                self.logger.error("Phase 2 if_name mismatch")
                return 0
            if not uuid_dpae == str(db_result[u'uuid_dpae']):
                self.logger.error("Phase 2 uuid_dpae mismatch")
                return 0
            self.logger.debug("Phase 2 updating DPAE record")
            db_result = self.dbdpae.update_one(
                        {'_id': str(uuid_controller)},
                        {
                            '$set': {
                                'dpid': datapath.id,
                                'switch_port': in_port
                            },
                        }
                    )
            self.logger.debug("Phase 2 updated %s database record(s)",
                                    db_result.modified_count)
        else:
            #*** Ignore as no uuid_controller key:
            self.logger.debug("Phase 2 discovery packet uuid_controller field "
                                    "not found in database, so ignoring...")
            return 0

    def tc_advice_id(self, dpid, tc_type, tc_subtype, src_mac, detail1):
        """
        Process a Traffic Classification advice message from a DPAE
        that relates to an identity
        """
        switch = self.switches[dpid]
        #*** TBD, deal with context:
        context = self.context_default
        #*** Look up source mac to get a port number:
        port_number = switch.mactable.mac2port(src_mac, context)

        #*** TBD, handle return value for port not found...

        if tc_subtype == 'lldp':
            #*** Check to see if we already know this identity:
            db_data = {'id_type': tc_subtype,
                'src_mac': src_mac, 'node_name': detail1}
            db_result = self.dbidnode.find_one(db_data)
            if not db_result:
                #*** LLDP identity not in database so add it:
                db_data = {'last_seen': time.time(), 'id_type': tc_subtype,
                                    'src_mac': src_mac, 'node_name': detail1}
                db_result = self.dbidnode.insert_one(db_data)
                self.logger.info("Created new ID Node record id_type=%s "
                            "node_name=%s", tc_subtype, detail1)
                #*** Check to see if we need to add a flow to switch:
                switch.flowtables.add_fe_tc_id(tc_subtype, detail1, src_mac,
                                  self.main_policy.optimised_rules.get_rules())
            else:
                #*** Just update the last_seen field:
                db_result = self.dbdpae.update_one(
                        {'id_type': tc_subtype,
                            'src_mac': src_mac, 'node_name': detail1},
                        {
                            '$set': {
                                'last_seen': time.time()
                            },
                        }
                    )
                self.logger.debug("Last seen updated for %s of %s ID Node "
                                    "record(s) id_type=%s  node_name=%s",
                                    db_result.modified_count,
                                    db_result.matched_count,
                                    tc_subtype, detail1)
        else:
            self.logger.info("Didn't action tc_subtype=%s", tc_subtype)

    def _packet_in_debug(self, ev, in_port):
        """
        Generate a debug message describing the packet
        in event
        """
        #*** Extract parameters:
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_src = eth.src
        eth_dst = eth.dst
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        #*** Some debug about the Packet In:
        if pkt_ip4 and pkt_tcp:
            self.logger.debug("event=pi_ipv4_tcp dpid=%s "
                                  "in_port=%s ip_src=%s ip_dst=%s tcp_src=%s "
                                  "tcp_dst=%s",
                                  dpid, in_port, pkt_ip4.src, pkt_ip4.dst,
                                  pkt_tcp.src_port, pkt_tcp.dst_port)
        elif pkt_ip6 and pkt_tcp:
            self.logger.debug("event=pi_ipv6_tcp dpid=%s "
                                  "in_port=%s ip_src=%s ip_dst=%s tcp_src=%s "
                                  "tcp_dst=%s",
                                  dpid, in_port, pkt_ip6.src, pkt_ip6.dst,
                                  pkt_tcp.src_port, pkt_tcp.dst_port)
        elif pkt_ip4:
            self.logger.debug("event=pi_ipv4 dpid="
                                  "%s in_port=%s ip_src=%s ip_dst=%s proto=%s",
                                  dpid, in_port,
                                  pkt_ip4.src, pkt_ip4.dst, pkt_ip4.proto)
        elif pkt_ip6:
            self.logger.debug("event=pi_ipv6 dpid=%s "
                                  "in_port=%s ip_src=%s ip_dst=%s",
                                  dpid, in_port,
                                  pkt_ip6.src, pkt_ip6.dst)
        else:
            self.logger.debug("event=pi_other dpid=%s "
                                "in_port=%s eth_src=%s eth_dst=%s eth_type=%s",
                                dpid, in_port, eth_src, eth_dst, eth.ethertype)

