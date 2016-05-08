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

#*** nmeta2 - Network Metadata - Abstractions of Controller for OpenFlow Calls

"""
This module is part of the nmeta suite running on top of Ryu SDN controller.
It provides functions that abstract the details of OpenFlow calls, including
differences between OpenFlow versions where practical
"""

#*** Logging Imports:
import logging
import logging.handlers

#*** General Imports:
import sys
import struct
import re

#*** Ryu Imports:
from ryu.lib.mac import haddr_to_bin
from ryu.lib import addrconv
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import tcp

#*** Constant to use for a port not found value:
PORT_NOT_FOUND = 999999999

class Switches(object):
    """
    This class provides an abstraction for a set of OpenFlow
    Switches
    """
    def __init__(self, _nmeta, _config):
        self._nmeta = _nmeta
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('sa_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('sa_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
        _coloredlogs_enabled = _config.get_value('coloredlogs_enabled')
        _console_format = _config.get_value('console_format')
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
        #*** Registration MAC address:
        self.dpae2ctrl_mac = _config.get_value("dpae2ctrl_mac")
        #*** MAC Address idle timeouts for flow entries in switches:
        self.mac_iim_idle_timeout = _config.get_value("mac_iim_idle_timeout")
        self.mac_fwd_idle_timeout = _config.get_value("mac_fwd_idle_timeout")
        #*** Dictionary of switches indexed by dpid:
        self.switch = {}
        self._config = _config

    def add(self, datapath):
        """
        Add a switch to the class
        """
        self.logger.debug("Adding switch dpid=%s", datapath.id)
        self.switch[datapath.id] = Switch(self._nmeta, self.logger,
                                            self._config, datapath)
        return 1

    def datapath(self, dpid):
        """
        Return a datapath for a given switch dpid
        """
        if dpid in self.switch:
            return self.switch[dpid].datapath
        else:
            self.logger.error("Unknown dpid=%s", dpid)
            return 0

    def __getitem__(self, key):
        """
        Passed a dpid key and return corresponding switch
        object, or 0 if it doesn't exist.
        Example:
            switch = switches[dpid]
        """
        if key in self.switch:
            return self.switch[key]
        else:
            return 0

class Switch(object):
    """
    This class provides an abstraction for an OpenFlow
    Switch
    """
    def __init__(self, _nmeta, logger, _config, datapath):
        self._nmeta = _nmeta
        self.logger = logger
        self.datapath = datapath
        self.dpid = datapath.id
        self._config = _config
        #*** Instantiate a class that represents flow tables:
        self.flowtables = FlowTables(self._nmeta, self.logger, self._config,
                                            datapath)
        #*** Instantiate a class that represents the MAC table:
        self.mactable = MACTable(self._nmeta, self.logger, self._config,
                                            datapath)

    def request_switch_desc(self):
        """
        Send an OpenFlow request to the switch asking it to
        send us it's description data
        """
        parser = self.datapath.ofproto_parser
        req = parser.OFPDescStatsRequest(self.datapath, 0)
        self.logger.debug("Sending description request to dpid=%s",
                            self.datapath.id)
        self.datapath.send_msg(req)

    def set_switch_config(self, config_flags, miss_send_len):
        """
        Set config on a switch including config flags that
        instruct fragment handling behaviour and miss_send_len
        which controls the number of bytes sent to the controller
        when the output port is specified as the controller.
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Setting config on switch "
                         "dpid=%s to config_flags flag=%s and "
                         "miss_send_len=%s bytes",
                          self.dpid, config_flags, miss_send_len)
        try:
            self.datapath.send_msg(parser.OFPSetConfig(
                                     self.datapath,
                                     config_flags,
                                     miss_send_len))
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Failed to set switch config. "
                   "Exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
            return 0
        return 1

    def get_friendly_of_version(self, ofproto):
        """
        Passed an OF Protocol object and return a
        human-friendly version of the protocol
        revision number
        """
        if ofproto.OFP_VERSION == 1:
            _of_version = "1.0"
        elif ofproto.OFP_VERSION == 4:
            _of_version = "1.3"
        else:
            _of_version = "Unknown version " + \
                            str(ofproto.OFP_VERSION)
        return _of_version

    def packet_out(self, data, in_port, out_port, out_queue, nq=0):
        """
        Sends a supplied packet out switch port(s) in specific queue.
        Set nq=1 if want no queueing specified (i.e. for a flooded
        packet)
        Does not support use of Buffer IDs
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        dpid = self.datapath.id
        #*** First build OF version specific list of actions:
        if not nq:
            #*** Packet out with no queue (nq):
            actions = [self.datapath.ofproto_parser.OFPActionOutput \
                             (out_port, 0)]

        else:
            #*** Note: out_port must come last!
            actions = [
                    parser.OFPActionSetQueue(out_queue),
                    parser.OFPActionOutput(out_port, 0)]

        #*** Now have we have actions, build the packet out message:
        out = parser.OFPPacketOut(
                    datapath=self.datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=data)

        self.logger.debug("Sending Packet-Out message dpid=%s port=%s",
                                    dpid, out_port)
        #*** Tell the switch to send the packet:
        self.datapath.send_msg(out)

class MACTable(object):
    """
    This class provides an abstraction for the MAC table on
    an OpenFlow Switch that maps MAC addresses to switch ports
    """

    def __init__(self, _nmeta, logger, _config, datapath):
        self._nmeta = _nmeta
        self.logger = logger
        self.datapath = datapath
        self.dpid = datapath.id
        self._config = _config
        self.parser = datapath.ofproto_parser

    def add(self, mac, in_port, context):
        """
        Passed a MAC address and the switch port it was learnt
        via along with a context. Add this to the database and
        tidy up by removing any other entries for this MAC on
        this switch in given context.
        """
        nmeta = self._nmeta
        dpid = self.dpid

        #*** Check if MAC known in database for this switch/context:
        db_result = nmeta.dbidmac.find_one({'dpid': dpid, 'mac': mac,
                                                    'context': context})
        if db_result and db_result['port'] != in_port:
            #*** We've learnt MAC via a different port so need to update:
            self.logger.debug("MAC/port formerly known as: dpid=%s mac=%s "
                            "port=%s context=%s", dpid, mac, in_port, context)
            # TBD

        #*** Record in database:
        self.logger.debug("Adding MAC/port to DB: dpid=%s mac=%s port=%s "
                            "context=%s", dpid, mac, in_port, context)
        dbidmac_doc = {'dpid': dpid, 'mac': mac, 'port': in_port,
                         'context': context}
        db_id = nmeta.dbidmac.insert_one(dbidmac_doc).inserted_id

    def mac2port(self, mac, context):
        """
        Passed a dpid and mac address and return the switch port number
        that this mac has been learned via
        (or 999999999 if unknown)
        """
        nmeta = self._nmeta
        dpid = self.dpid
        #*** Retrieve first matching record:
        db_result = nmeta.dbidmac.find_one({'dpid': dpid, 'mac': mac,
                                                'context': context})
        if db_result:
            if not 'dpid' in db_result:
                self.logger.error("DB record didn't have a dpid...???")
                return PORT_NOT_FOUND
            dpid = db_result['dpid']
            if not 'port' in db_result:
                self.logger.error("DB record didn't have a port...???")
                return PORT_NOT_FOUND
            if not 'context' in db_result:
                self.logger.error("DB record didn't have a context...???")
                return PORT_NOT_FOUND
            if db_result['context'] != context:
                return PORT_NOT_FOUND
            port = db_result['port']
            self.logger.debug("Found mac=%s on dpid=%s port=%s context=%s",
                                        mac, dpid, port, context)
            return port
        else:
            self.logger.info("Unknown mac=%s for dpid=%s context=%s", mac,
                                        self.dpid, context)
        return PORT_NOT_FOUND

class FlowTables(object):
    """
    This class provides an abstraction for the flow tables on
    an OpenFlow Switch
    """
    def __init__(self, _nmeta, logger, _config, datapath):
        self._nmeta = _nmeta
        self.logger = logger
        self.datapath = datapath
        self.dpid = datapath.id
        self._config = _config
        self.parser = datapath.ofproto_parser
        self.dpae2ctrl_mac = _config.get_value("dpae2ctrl_mac")
        #*** Load the Flow Table ID numbers:
        self.ft_iig = self._config.get_value("ft_iig")
        self.ft_iim = self._config.get_value("ft_iim")
        self.ft_tcf = self._config.get_value("ft_tcf")
        self.ft_tc = self._config.get_value("ft_tc")
        self.ft_tt = self._config.get_value("ft_tt")
        self.ft_fwd = self._config.get_value("ft_fwd")
        self.ft_group_dpae = self._config.get_value("ft_group_dpae")
        #*** MAC aging:
        self.mac_iim_idle_timeout = \
                            self._config.get_value("mac_iim_idle_timeout")
        self.mac_fwd_idle_timeout = \
                            self._config.get_value("mac_fwd_idle_timeout")
        #*** Timeout for FEs suppressing traffic sending to DPAE:
        self.suppress_idle_timeout = _config.get_value("suppress_idle_timeout")
        #*** Timeout for a dynamic QoS treatment FE:
        self.fe_idle_timeout_qos = _config.get_value("fe_idle_timeout_qos")

    def add_fe_iig_dpae_join(self):
        """
        Add Identity Indicator (General) Flow Entry to
        send DPAE Join packets to the controller as
        packet-in messages
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        priority = 4
        self.logger.info("Adding Identity Indicator (General) flow table flow "
                         "entry for DPAE Join to dpid=%s", self.dpid)
        match = parser.OFPMatch(eth_dst=self.dpae2ctrl_mac)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                table_id=self.ft_iig, priority=priority,
                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_iig_dpae_active_bypass(self, dpae_port):
        """
        Add Identity Indicator (General) Flow Entry to
        bypass intermediate tables for traffic from DPAE
        (return packets from active mode TC) and goto
        treatment table direct
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        priority = 3
        self.logger.info("Adding Identity Indicator (General) flow table flow "
                         "entry for DPAE return traffic bypass to dpid=%s",
                         self.dpid)
        match = parser.OFPMatch(in_port=dpae_port)
        actions = []
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_tt)]
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                table_id=self.ft_iig, priority=priority,
                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_iig_lldp(self, dpae_port):
        """
        Add Flow Entry (FE) to the Identity Indicators (General)
        flow table to clone LLDP packets to a DPAE
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        priority = 2
        #*** LLDP:
        match = parser.OFPMatch(eth_type=0x88CC)
        actions = [parser.OFPActionOutput(dpae_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing LLDP to DPAE flow in dpid=%s via port"
                            "=%s", self.dpid, dpae_port)
        self.datapath.send_msg(mod)

    def add_fe_iig_dhcp(self, dpae_port):
        """
        Add Flow Entry (FE) to the Identity Indicators (General)
        flow table to clone DHCP packets to a DPAE
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        priority = 2
        #*** DHCP:
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=67)
        actions = [parser.OFPActionOutput(dpae_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iig + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing DHCP src port to DPAE flow in dpid=%s "
                            "via port=%s", self.dpid, dpae_port)
        self.datapath.send_msg(mod)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=67)
        actions = [parser.OFPActionOutput(dpae_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iig + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing DHCP dst port to DPAE flow in dpid=%s "
                            "via port=%s", self.dpid, dpae_port)
        self.datapath.send_msg(mod)

    def add_fe_iig_dns(self, dpae_port):
        """
        Add Flow Entry (FE) to the Identity Indicators (General)
        flow table to clone DNS packets to a DPAE
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        priority = 2
        #*** UDP DNS (a FE each for source and destination UDP 53):
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=53)
        actions = [parser.OFPActionOutput(dpae_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iig + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing DNS UDP src port to DPAE flow in dpid=%s"
                            " via port=%s", self.dpid, dpae_port)
        self.datapath.send_msg(mod)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=53)
        actions = [parser.OFPActionOutput(dpae_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iig + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing DNS UDP dst port to DPAE flow in dpid=%s"
                            " via port=%s", self.dpid, dpae_port)
        self.datapath.send_msg(mod)
        #*** TCP DNS (a FE each for source and destination TCP 53):
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_src=53)
        actions = [parser.OFPActionOutput(dpae_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iig + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing DNS TCP src port to DPAE flow in dpid=%s"
                            " via port=%s", self.dpid, dpae_port)
        self.datapath.send_msg(mod)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=53)
        actions = [parser.OFPActionOutput(dpae_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iig + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing DNS TCP dst port to DPAE flow in dpid=%s"
                            " via port=%s", self.dpid, dpae_port)
        self.datapath.send_msg(mod)

    def add_fe_iig_broadcast(self):
        """
        Add Flow Entry (FE) to the Identity Indicators (General)
        flow table to flood Ethernet broadcast packets to
        lower the load on the rest of the pipeline
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        priority = 1
        #*** Ethernet Broadcast:
        match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                            priority=priority, match=match, instructions=inst)
        self.logger.debug("Installing Eth broadcast flood rule to dpid=%s",
                                                                self.dpid)
        self.datapath.send_msg(mod)

    def add_fe_iig_miss(self):
        """
        Add Identity Indicator (General) flow table miss Flow Entry
        to continue pipeline processing
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Adding Identity Indicator (MAC) flow table miss"
                         " flow entry to dpid=%s", self.dpid)
        match = parser.OFPMatch()
        actions = []
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iig + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iig,
                                priority=0, match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_iim_miss(self):
        """
        Add Identity Indicator (MAC) flow table miss Flow Entry
        to clone a table-miss packet to the controller as a
        packet-in message and also send the packet to the next
        Flow Table so that it continues pipeline processing
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Adding Identity Indicator (MAC) flow table miss"
                         " flow entry to dpid=%s", self.dpid)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iim + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iim,
                                priority=0, match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_tt_advised(self, flow_dict):
        """
        Process a Traffic Classification flow treatment advice
        from a DPAE. Install an FE to switch for each direction
        of the flow applying the appropriate treatment.
        .
        Only supports IPv4 and TCP at this stage.
        .
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        #*** Check it's TCP:
        if flow_dict['proto'] != 'tcp':
            self.logger.error("Unsupported proto=%s", flow_dict['proto'])
            return 0

        #*** Convert IP addresses strings to integers:
        ipv4_src = _ipv4_t2i(str(flow_dict['ip_A']))
        ipv4_dst = _ipv4_t2i(str(flow_dict['ip_B']))

        #*** Build match:
        match = parser.OFPMatch(eth_type=0x0800,
                    ipv4_src=ipv4_src,
                    ipv4_dst=ipv4_dst,
                    ip_proto=6,
                    tcp_src=flow_dict['tp_A'],
                    tcp_dst=flow_dict['tp_B']
                    )

        #*** Set QoS actions (if any):
        queue = 0
        self.logger.debug("flow_dict=%s", flow_dict)

        if flow_dict['actions'] and 'qos_treatment' in flow_dict:
            qos = flow_dict['qos_treatment']
            self.logger.debug("qos_treatment=%s", qos)
            queue = self._nmeta.main_policy.qos_treatment.\
                                            get_policy_qos_treatment_value(qos)
            self.logger.debug("queue=%s", queue)
        if queue:
            actions = [parser.OFPActionSetQueue(queue)]
        else:
            actions = []

        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_tt + 1)]
        priority = 1
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_tt,
                            priority=priority,
                            idle_timeout=self.fe_idle_timeout_qos,
                            match=match, instructions=inst)
        self.logger.debug("Installing dynamic treatment forward FE dpid=%s",
                                    self.dpid)
        self.datapath.send_msg(mod)
        #*** Build counter match (reversed flow):
        match = parser.OFPMatch(eth_type=0x0800,
                    ipv4_src=ipv4_dst,
                    ipv4_dst=ipv4_src,
                    ip_proto=6,
                    tcp_src=flow_dict['tp_B'],
                    tcp_dst=flow_dict['tp_A']
                    )
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_tt,
                            priority=priority,
                            idle_timeout=self.fe_idle_timeout_qos,
                            match=match, instructions=inst)
        self.logger.debug("Installing dynamic treatment reverse FE dpid=%s",
                                        self.dpid)
        self.datapath.send_msg(mod)

    def add_fe_tcf_suppress(self, suppress_dict):
        """
        Process a Traffic Classification flow suppression request
        from a DPAE, where it has requested that we don't send any
        more packets to it for a specific flow. Install an FE to
        switch for each direction of the flow to bypass sending to DPAE.
        .
        Only supports IPv4 and TCP at this stage.
        .
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        #*** Check it's TCP:
        if suppress_dict['proto'] != 'tcp':
            self.logger.error("Unsupported proto=%s", suppress_dict['proto'])
            return 0

        #*** Convert IP addresses strings to integers:
        ipv4_src = _ipv4_t2i(str(suppress_dict['ip_A']))
        ipv4_dst = _ipv4_t2i(str(suppress_dict['ip_B']))

        #*** Build match:
        match = parser.OFPMatch(eth_type=0x0800,
                    ipv4_src=ipv4_src,
                    ipv4_dst=ipv4_dst,
                    ip_proto=6,
                    tcp_src=suppress_dict['tp_A'],
                    tcp_dst=suppress_dict['tp_B']
                    )
        actions = []
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_tcf + 2)]
        #*** Needs higher priority than TC rules in same table:
        priority = 2
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_tcf,
                            priority=priority,
                            idle_timeout=self.suppress_idle_timeout,
                            match=match, instructions=inst)
        self.logger.debug("Installing suppress forward FE dpid=%s", self.dpid)
        self.datapath.send_msg(mod)
        #*** Build counter match (reversed flow):
        match = parser.OFPMatch(eth_type=0x0800,
                    ipv4_src=ipv4_dst,
                    ipv4_dst=ipv4_src,
                    ip_proto=6,
                    tcp_src=suppress_dict['tp_B'],
                    tcp_dst=suppress_dict['tp_A']
                    )
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_tcf,
                            priority=priority,
                            idle_timeout=self.suppress_idle_timeout,
                            match=match, instructions=inst)
        self.logger.debug("Installing suppress reverse FE dpid=%s", self.dpid)
        self.datapath.send_msg(mod)

    def add_fe_tcf_accepts(self):
        """
        Add Traffic Classification Filter flow table accept Flow Entries
        to send packets to TC flow table)
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Adding ports to run TC on to dpid=%s", self.dpid)
        tc_ports = self._nmeta.main_policy.port_sets.get_tc_ports(self.dpid)
        for port in tc_ports:
            match = parser.OFPMatch(in_port=port)
            actions = []
            inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_tcf + 1)]
            mod = parser.OFPFlowMod(datapath=self.datapath,
                                table_id=self.ft_tcf, priority=1,
                                match=match, instructions=inst)
            self.logger.debug("Adding FE for TC on port=%s dpid=%s",
                                            port, self.dpid)
            self.datapath.send_msg(mod)

    def add_fe_tcf_miss(self):
        """
        Add Traffic Classification Filter flow table miss Flow Entry
        to send packets to next flow table + 1 (i.e. skip the TC
        flow table)
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Adding Traffic Classification Filter flow table miss"
                         " flow entry to dpid=%s", self.dpid)
        match = parser.OFPMatch()
        actions = []
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_tcf + 2)]
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                table_id=self.ft_tcf, priority=0,
                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_tc_miss(self):
        """
        Add Traffic Classification flow table miss Flow Entry
        to send packets to next flow table
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Adding Traffic Classification flow table miss"
                         " flow entry to dpid=%s", self.dpid)
        match = parser.OFPMatch()
        actions = []
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_tc + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                table_id=self.ft_tc, priority=0,
                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_tt_miss(self):
        """
        Add Traffic Treatment flow table miss Flow Entry
        to send packets to next flow table
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Adding Traffic Treatment flow table miss"
                         " flow entry to dpid=%s", self.dpid)
        match = parser.OFPMatch()
        actions = []
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_tt + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                table_id=self.ft_tt, priority=0,
                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_fwd_miss(self):
        """
        Add Forwarding flow table miss Flow Entry
        to flood packets out ports as we haven't learnt
        the MAC address
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        self.logger.info("Adding Forwarding flow table miss"
                         " flow entry to dpid=%s", self.dpid)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_fwd,
                                    priority=0, match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_iim_macport_src(self, in_port, eth_src):
        """
        Add Flow Entry (FE) to the Identity Indicator (MAC) flow table to
        match combo of in port and source MAC and goto next table. This is
        used filter punts to the controller for learning MAC to port mappings
        so that only new port/MAC mappings that aren't matched by a rule
        are punted by the Identity Indicator (MAC) flow table miss rule
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        #*** Priority needs to be greater than 0:
        priority = 1
        match = parser.OFPMatch(in_port=in_port, eth_src=eth_src)
        actions = []
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(self.ft_iim + 1)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_iim,
                            priority=priority,
                            idle_timeout=self.mac_iim_idle_timeout,
                            flags=ofproto.OFPFF_SEND_FLOW_REM,
                            match=match,
                            instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_fwd_macport_dst(self, out_port, eth_dst):
        """
        Add Flow Entry (FE) to the Forwarding flow table to
        match destination MAC and output learned port to avoid flooding
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        #*** Priority needs to be greater than 0:
        priority = 1
        match = parser.OFPMatch(eth_dst=eth_dst)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, table_id=self.ft_fwd,
                            priority=priority,
                            idle_timeout=self.mac_fwd_idle_timeout,
                            flags=ofproto.OFPFF_SEND_FLOW_REM,
                            match=match,
                            instructions=inst)
        self.datapath.send_msg(mod)

    def add_fe_tc_static(self, tc_flows):
        """
        Install non-DPAE static Traffic Classification (TC) flows from
        optimised TC policy to switch (i.e. Flow Entries that
        invoke actions without need for DPAE to classify)
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        flow_table = self.ft_tt
        #*** Priority needs to be greater than 0:
        priority = 1
        for idx, fe_match_list in enumerate(tc_flows):
            self.logger.info("Optimised fe_match_list %s is %s", idx,
                                        fe_match_list)
            if not 'install_type' in fe_match_list:
                self.logger.error("no install_type key")
                continue
            if not 'match' in fe_match_list:
                self.logger.error("no match key")
                continue
            if fe_match_list['install_type'] == 'immediate':
                self.logger.debug("Immediate flow entry install proceeding...")
                fe_matches = fe_match_list['match']
                #*** Add in prerequisite matches:
                fe_matches = self.matches_add_fe_prereqs(fe_matches)
                #*** Create Ryu OpenFlow match from FE match list rule:
                match = parser.OFPMatch(**fe_matches)
                #*** Actions (TBD needs work to make extensible as
                #***  is QoS specific):
                fe_action = fe_match_list['action']
                actions = []
                if 'Set-Queue' in fe_action:
                    #*** Set QoS Output Queue:
                    queue_num = fe_action['Set-Queue']
                    actions = \
                        [parser.OFPActionSetQueue(queue_num)]
                #*** Build the instructions for the FE:
                inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(flow_table + 1)]
                #*** Put it all together and install to switch:
                mod = parser.OFPFlowMod(datapath=self.datapath,
                            table_id=flow_table,
                            priority=priority,
                            match=match,
                            instructions=inst)
                self.datapath.send_msg(mod)
            else:
                self.logger.info("Not installing to switch at this stage")

    def add_fe_tc_dpae(self, tc_flows, dpae_port, mode):
        """
        Install DPAE Traffic Classification (TC) flows from
        optimised TC policy to switch (i.e. Flow Entries that
        invoke actions that need for DPAE to classify).
        Mode is either active or passive. For the former, we
        don't do a goto-table instruction.
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        flow_table = self.ft_tc
        #*** Priority needs to be greater than 0:
        priority = 1
        for idx, fe_match_list in enumerate(tc_flows):
            self.logger.info("Optimised fe_match_list %s is %s", idx,
                                        fe_match_list)
            if not 'install_type' in fe_match_list:
                self.logger.error("no install_type key")
                continue
            if not 'match' in fe_match_list:
                self.logger.error("no match key")
                continue
            if fe_match_list['install_type'] == 'to_dpae':
                self.logger.debug("Switch TC to DPAE FE install proceeding...")
                fe_matches = fe_match_list['match']
                if fe_matches == 'any':
                    match = parser.OFPMatch()
                else:
                    #*** Add in prerequisite matches:
                    fe_matches = self.matches_add_fe_prereqs(fe_matches)
                    #*** Create Ryu OpenFlow match from FE match list rule:
                    match = parser.OFPMatch(**fe_matches)
                #*** Actions (TBD needs work to make extensible as
                #***  is QoS specific):
                fe_action = fe_match_list['action']
                actions = []
                if 'Set-Queue' in fe_action:
                    #*** Set QoS Output Queue:
                    queue_num = fe_action['Set-Queue']
                    actions.append(parser.OFPActionSetQueue(queue_num))
                #*** Set the output port in any parser.OFPActionOutput actions:
                if 'parser.OFPActionOutput(dpae_port)' in fe_action:
                    actions.append(parser.OFPActionOutput(dpae_port))
                #*** Build the instructions for the FE:
                if mode == 'passive':
                    inst = [parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS, actions),
                            parser.OFPInstructionGotoTable(flow_table + 1)]
                elif mode == 'active':
                    inst = [parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS, actions)]
                else:
                    #*** This is a bad condition...
                    self.logger.error("unknown mode, mode=%s", mode)
                    return 0
                #*** Put it all together and install to switch:
                mod = parser.OFPFlowMod(datapath=self.datapath,
                            table_id=flow_table,
                            priority=priority,
                            match=match,
                            instructions=inst)
                self.datapath.send_msg(mod)
                return 1

    def add_fe_tc_id(self, id_type, id_detail, id_mac, tc_flows):
        """
        Add Flow Entri(es) to the switch if required for
        identity match and action. Check to see if we
        have any to install, and if so use a separate
        function to install to switch
        """
        for idx, fe_match_list in enumerate(tc_flows):
            if not 'install_type' in fe_match_list:
                self.logger.error("no install_type key")
                continue
            if not 'match' in fe_match_list:
                self.logger.error("no match key")
                continue
            #*** We're only interested in 'on_identity' matches:
            if fe_match_list['install_type'] == 'on_identity':
                fe_matches = fe_match_list['match']
                self.logger.debug("Checking for identity install on ..."
                                    "fe_matches=%s", fe_matches)
                for id_match_type in fe_matches:
                    if id_match_type == 'identity_lldp_systemname':
                        #*** Check full match:
                        if fe_matches[id_match_type] == id_detail:
                            self.add_fe_tc_id_install(id_mac,
                                        fe_match_list['action'])
                    elif id_match_type == 'identity_lldp_systemname_re':
                        #*** Check regular expression match:
                        if re.match(fe_matches[id_match_type], id_detail):
                            self.logger.debug("RE match on %s == %s",
                                        fe_matches[id_match_type], id_detail)
                            #*** Now, install flow to switch...
                            self.add_fe_tc_id_install(id_mac,
                                                    fe_match_list['action'])
                    elif id_match_type == 'identity_service_dns':
                        #*** TBD:
                        self.logger.error("identity_service_dns match is not "
                                                "implemented yet")
                    elif id_match_type == 'identity_service_dns_re':
                        #*** TBD:
                        self.logger.error("identity_service_dns_re match is "
                                                "not implemented yet")
                    else:
                        self.logger.error("Unknown id_match_type=%s",
                                                id_match_type)

    def add_fe_tc_id_install(self, id_mac, action):
        """
        Add Flow Entry to the switch for
        identity match and action
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        flow_table = self.ft_tt
        #*** Priority needs to be greater than 0:
        priority = 1
        #*** Set the action:
        if 'Set-Queue' in action:
            #*** Set QoS Output Queue:
            queue_num = action['Set-Queue']
            actions = [parser.OFPActionSetQueue(queue_num)]
        else:
            self.logger.error("No supported actions for id match actions=%s",
                                    action)
            return 0
        #*** Set the match (mac as src):
        match = parser.OFPMatch(eth_src=id_mac)
        #*** Build the instructions for the FE:
        inst = [parser.OFPInstructionActions(
                                ofproto.OFPIT_APPLY_ACTIONS, actions),
                                parser.OFPInstructionGotoTable(flow_table + 1)]
        #*** Put it all together and install to switch:
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                    table_id=flow_table,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        #*** Install to switch:
        self.logger.debug("Installing id match src mac=%s to dpid=%s",
                                                id_mac, self.dpid)
        self.datapath.send_msg(mod)
        #*** Set the match (mac as dst):
        match = parser.OFPMatch(eth_dst=id_mac)
        #*** Build the instructions for the FE:
        inst = [parser.OFPInstructionActions(
                                ofproto.OFPIT_APPLY_ACTIONS, actions),
                                parser.OFPInstructionGotoTable(flow_table + 1)]
        #*** Put it all together and install to switch:
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                    table_id=flow_table,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        #*** Install to switch:
        self.logger.debug("Installing id match dst mac=%s to dpid=%s",
                                                id_mac, self.dpid)
        self.datapath.send_msg(mod)
        return 1

    def add_group_dpae(self, dpae_port):
        """
        Add Group Table to the switch for forwarding packets to
        DPAE out a specific port.
        Note, will generate error if group table already exists.
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser

        #*** Group Flow Table ID, from config:
        group_id = self.ft_group_dpae

        #*** Set the actions:
        actions = [parser.OFPActionOutput(dpae_port)]

        #*** Set up the bucket:
        weight = 100
        watch_port = 0
        watch_group = 0
        buckets = [parser.OFPBucket(weight, watch_port, watch_group,
                                    actions)]

        #*** Build request:
        mod = parser.OFPGroupMod(self.datapath, ofproto.OFPGC_ADD,
                                 ofproto.OFPGT_INDIRECT, group_id, buckets)

        #*** Install to switch:
        self.logger.debug("Installing group table id=%s to send to DPAE "
                                "via port=%s", group_id, dpae_port)
        self.datapath.send_msg(mod)
        return 1

    def matches_add_fe_prereqs(self, fe_matches):
        """
        Passed a dictionary of match_type, value pairs for creating
        a flow entry on a switch and work out what match types are
        missing as per requirements of OpenFlow v1.3 standard and add
        them to the dictionary
        """
        #*** This assumes that policy doesn't do dumb stuff like try
        #***  to match tcp and udp in same rule...
        #
        #*** TBD: expand this to deal with all prerequisites and write tests

        if 'tcp_src' in fe_matches or 'tcp_dst' in fe_matches:
            #*** Set ip protocol to TCP
            fe_matches['ip_proto'] = 6
        if 'udp_src' in fe_matches or 'udp_dst' in fe_matches:
            #*** Set ip protocol to UDP
            fe_matches['ip_proto'] = 17
        if 'ip_proto' in fe_matches:
            #*** Set eth_type to IP:
            fe_matches['eth_type'] = 2048
        return fe_matches

    def delete_fe(self, match, flow_table_id):
        """
        Delete a specific FE from a specific Flow Table on
        this switch
        """
        #*** TBD:
        pass

    def delete_all_flows(self):
        """
        Delete all Flow Entries from all Flow Tables on
        this switch
        """
        parser = self.datapath.ofproto_parser
        self.logger.debug("About to delete all flows from dpid=%s",
                                self.dpid)
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(self.datapath, 0, 0,
                                            self.datapath.ofproto.OFPTT_ALL,
                                            self.datapath.ofproto.OFPFC_DELETE,
                                            0, 0, 0, 0xffffffff,
                                            self.datapath.ofproto.OFPP_ANY,
                                            self.datapath.ofproto.OFPG_ANY,
                                            0, match, [])
        try:
            #*** Tell the switch to delete all flows:
            self.datapath.send_msg(mod)
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Error deleting all flows from dpid=%s,"
               "Exception is %s, %s, %s",
                self.dpid, exc_type, exc_value, exc_traceback)
            return 0
        return 1

#=============== Private functions:

def _ipv4_t2i(ip_text):
    """
    Turns an IPv4 address in text format into an integer.
    Borrowed from rest_router.py code
    """
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
