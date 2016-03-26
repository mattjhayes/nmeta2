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

#*** nmeta - Network Metadata - Policy Interpretation Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide network identity and flow metadata.
.
It provides an object for the traffic classification policy
and includes ingesting the policy from file on class instatiation
and validating its syntax.
.
Version 2.x Toulouse Code
"""

#*** Logging imports:
import logging
import logging.handlers

#*** OS imports:
import sys
import os

#*** Import netaddr for IP address checking:
from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import EUI

#*** YAML for config and policy file parsing:
import yaml

#*** Describe supported syntax in main_policy.yaml so that it can be tested
#*** for validity. Here are valid policy rule attributes:
TC_CONFIG_POLICYRULE_ATTRIBUTES = ('comment',
                                   'match_type',
                                   'conditions_list',
                                   'actions')

#*** Dictionary of valid conditions stanza attributes with type:
TC_CONFIG_CONDITIONS = {'eth_src': 'MACAddress',
                               'eth_dst': 'MACAddress',
                               'ip_src': 'IPAddressSpace',
                               'ip_dst': 'IPAddressSpace',
                               'tcp_src': 'PortNumber',
                               'tcp_dst': 'PortNumber',
                               'eth_type': 'EtherType',
                               'identity_lldp_systemname': 'String',
                               'identity_lldp_systemname_re': 'String',
                               'identity_service_dns': 'String',
                               'identity_service_dns_re': 'String',
                               'payload_type': 'String',
                               'statistical': 'String',
                               'match_type': 'MatchType',
                               'conditions_list': 'PolicyConditions'}

#*** Dictionary of valid actions:
TC_CONFIG_ACTIONS = ('set_qos',
                     'set_desc',
                     'classifier_return')

#*** Dictionary of valid match types:
TC_CONFIG_MATCH_TYPES = ('any',
                         'all')

#*** Keys that must exist under 'identity' in the policy:
IDENTITY_KEYS = ('arp',
                 'lldp',
                 'dns',
                 'dhcp')

#*** Keys that must exist under 'qos_treatment' in the policy:
QOS_TREATMENT_KEYS = ('default_priority',
                        'constrained_bw',
                        'high_priority',
                        'low_priority')

#*** Dictionary that maps conditions to TC type:
CONDITION_TYPES = {
                    'eth_src': 'static',
                    'eth_dst': 'static',
                    'ip_src': 'static',
                    'ip_dst': 'static',
                    'tcp_src': 'static',
                    'tcp_dst': 'static',
                    'eth_type': 'static',
                    'identity_lldp_systemname': 'identity',
                    'identity_lldp_systemname_re': 'identity',
                    'identity_service_dns': 'identity',
                    'identity_service_dns_re': 'identity',
                    'payload_type': 'payload',
                    'statistical': 'statistical'
                        }


class TCPolicy(object):
    """
    This class is instantiated by nmeta2.py and provides methods
    to ingest the policy file main_policy.yaml and validate
    that it is correctly structured
    """
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('tc_policy_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('tc_policy_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
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

        #*** Get TC policy file information from config:
        config_directory = _config.get_value('config_directory')
        tc_policy_filename = _config.get_value('tc_policy_filename')

        #*** Ingest TC policy from file:
        self.tc_policy_yaml = self.ingest_policy(config_directory,
                                                tc_policy_filename)

        #*** Run a test on the ingested traffic classification policy
        #***  to ensure that it is good:
        self.validate_policy(self.tc_policy_yaml)

        #*** Create a set of optimised rules that can be installed onto
        #***  switches from the TC policy:
        self.optimised_rules = self._optimise()
        self.logger.debug("Optimised rules are %s", self.optimised_rules)

    def ingest_policy(self, config_directory, tc_policy_filename):
        """
        Read in TC policy from file
        """
        #*** Get working directory:
        working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        self.fullpathname = os.path.join(working_directory,
                                         config_directory,
                                         tc_policy_filename)
        self.logger.info("About to open config file=%s", self.fullpathname)
        #*** Ingest the policy file:
        try:
            with open(self.fullpathname, 'r') as filename:
                _main_policy = yaml.load(filename)
        except (IOError, OSError) as exception:
            self.logger.error("Failed to open policy "
                              "file=%s exception=%s",
                              self.fullpathname, exception)
            sys.exit("Exiting nmeta. Please create traffic classification "
                             "policy file")
        return _main_policy

    def get_policy(self):
        """
        Return TC policy in YAML
        """
        return self.tc_policy_yaml

    def get_policy_id_value(self, id_key):
        """
        Return a value for a given key under the 'identity' root of
        the policy
        """
        if not id_key in IDENTITY_KEYS:
            self.logger.error("The key %s is not valid", id_key)
            return 0
        return self.tc_policy_yaml['identity'][id_key]

    def get_policy_qos_treatment_value(self, qos_key):
        """
        Return a value for a given key under the 'qos_treatment' root of
        the policy
        """
        if not id_key in QOS_TREATMENT_KEYS:
            self.logger.error("The key %s is not valid", id_key)
            return 0
        return self.tc_policy_yaml['qos_treatment'][qos_key]

    def get_tc_ports(self, dpid):
        """
        Passed a DPID and return a tuple of port numbers on which to
        run TC on that switch, or 0 if none
        """
        #*** TBD, this is hardcoded to this name, needs fixing:
        port_set = self.tc_policy_yaml['port_sets']['all_access_ports']
        for switchdict in port_set:
            switchdict2 = switchdict.itervalues().next()
            if switchdict2['DPID'] == dpid:
                ports = switchdict2['ports']
                self.logger.debug("found ports=%s dpid=%s", ports, dpid)
                #*** turn the ports spec into a list:
                result = []
                for part in ports.split(','):
                    if '-' in part:
                        a, b = part.split('-')
                        a, b = int(a), int(b)
                        result.extend(range(a, b + 1))
                    else:
                        a = int(part)
                        result.append(a)
        self.logger.debug("result is %s", result)
        return result

    def validate_policy(self, tc_policy_yaml):
        """
        Check main policy to ensure that it is in
        correct format so that it won't cause unexpected errors during
        packet checks.
        """
        self.logger.debug("Validating main policy...")
        #*** Validate that policy has a 'tc_policies' key off the root:
        if not 'tc_policies' in tc_policy_yaml:
            #*** No 'tc_policies' key off the root, so log and exit:
            self.logger.critical("Missing tc_policies"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Validate that policy has a 'tc_rules' key off the root:
        if not 'tc_rules' in tc_policy_yaml:
            #*** No 'tc_rules' key off the root, so log and exit:
            self.logger.critical("Missing tc_rules"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Get the tc ruleset name, only one ruleset supported at this stage:
        tc_rules_keys = list(tc_policy_yaml['tc_rules'].keys())
        if not len(tc_rules_keys) == 1:
            #*** Unsupported number of rulesets so log and exit:
            self.logger.critical("Unsupported "
                                    "number of tc rulesets. Should be 1 but "
                                    "is %s", len(tc_rules_keys))
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        tc_ruleset_name = tc_rules_keys[0]
        self.logger.debug("tc_ruleset_name=%s",
                              tc_ruleset_name)
        #*** Create new variable to reference tc ruleset directly:
        self.tc_ruleset = tc_policy_yaml['tc_rules'][tc_ruleset_name]
        for idx, tc_rule in enumerate(self.tc_ruleset):
            self.logger.debug("Validating PolicyRule "
                              "number=%s rule=%s", idx, tc_rule)
            #*** Test for unsupported PolicyRule attributes:
            for policy_rule_parameter in tc_rule.keys():
                if not policy_rule_parameter in \
                        TC_CONFIG_POLICYRULE_ATTRIBUTES:
                    self.logger.critical("The "
                                         "following PolicyRule attribute is "
                                         "invalid: %s ", policy_rule_parameter)
                    sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
                if policy_rule_parameter == 'conditions':
                    #*** Call function to validate the policy condition and
                    #*** any nested policy conditions that it may contain:
                    self._validate_conditions(tc_rule[policy_rule_parameter])
                if policy_rule_parameter == 'actions':
                    #*** Check actions are valid:
                    for action in tc_rule[policy_rule_parameter].keys():
                        if not action in TC_CONFIG_ACTIONS:
                            self.logger.critical("The following action "
                                                 "attribute is invalid: %s",
                                                 action)
                            sys.exit("Exiting nmeta. Please fix error in "
                                     "main_policy.yaml file")

        #*** Validate Identity portion of policy:
        self._validate_policy_identity(tc_policy_yaml)

        #*** Validate QoS treatment portion of policy:
        self._validate_policy_qos(tc_policy_yaml)

        #*** Validate Port Set portion of policy:
        self._validate_policy_portsets(tc_policy_yaml)

    def _validate_policy_identity(self, tc_policy_yaml):
        """
        Validate the completeness and correctness of the identity
        portion of the main policy under the key 'identity' off
        the root of the policy
        """
        if not 'identity' in tc_policy_yaml:
            #*** No 'identity' key off the root, so log and exit:
            self.logger.critical("Missing identity"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Get the identity keys and validate that they all exist in policy:
        for _id_key in IDENTITY_KEYS:
            if not _id_key in tc_policy_yaml['identity'].keys():
                self.logger.critical("Missing identity "
                                    "key in main policy: %s", _id_key)
                sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Conversely, check all identity keys in the policy are valid:
        for _id_pol_key in tc_policy_yaml['identity'].keys():
            if not _id_pol_key in IDENTITY_KEYS:
                self.logger.critical("Invalid identity "
                                    "key in main policy: %s", _id_pol_key)
                sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")

    def _validate_policy_qos(self, tc_policy_yaml):
        """
        Validate the completeness and correctness of the QoS
        portion of the main policy under the key 'qos_treatment'
        off the root of the policy
        """
        if not 'qos_treatment' in tc_policy_yaml:
            #*** No 'qos_treatment' key off the root, so log and exit:
            self.logger.critical("Missing qos_treatment"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Get the qos keys and validate that they all exist in policy:
        for _qos_key in QOS_TREATMENT_KEYS:
            if not _qos_key in tc_policy_yaml['qos_treatment'].keys():
                self.logger.critical("Missing qos_treatment "
                                    "key in main policy: %s", _qos_key)
                sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Conversely, check all QoS treatment keys in the policy are valid:
        for _qos_pol_key in tc_policy_yaml['qos_treatment'].keys():
            if not _qos_pol_key in QOS_TREATMENT_KEYS:
                self.logger.critical("Invalid qos_treatment "
                                    "key in main policy: %s", _qos_pol_key)
                sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")

    def _validate_policy_portsets(self, tc_policy_yaml):
        """
        Validate the completeness and correctness of the port sets
        portion of the main policy under the key 'port_sets'
        off the root of the policy
        """
        if not 'port_sets' in tc_policy_yaml:
            #*** No 'port_sets' key off the root, so log and exit:
            self.logger.critical("Missing port_sets"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** TBD...

    def _validate_conditions(self, policy_conditions):
        """
        Check Traffic Classification (TC) conditions stanza to ensure
        that it is in the correct format so that it won't cause unexpected
        errors during packet checks. Can recurse for nested policy conditions.
        """
        #*** Use this to check if there is a match_type in stanza. Note can't
        #*** check for more than one occurrence as dictionary will just
        #*** keep attribute and overwrite value. Also note that recursive
        #*** instances use same variable due to scoping:
        self.has_match_type = 0
        #*** Check conditions are valid:
        for policy_condition in policy_conditions.keys():
            #*** Check policy condition attribute is valid:
            if not (policy_condition in TC_CONFIG_CONDITIONS or
                     policy_condition[0:10] == 'conditions'):
                self.logger.critical("The following PolicyCondition attribute"
                " is invalid: %s", policy_condition)
                sys.exit("Exiting nmeta. Please fix error in "
                         "main_policy.yaml file")
            #*** Check policy condition value is valid:
            if not policy_condition[0:10] == 'conditions':
                pc_value_type = TC_CONFIG_CONDITIONS[policy_condition]
            else:
                pc_value_type = policy_condition
            pc_value = policy_conditions[policy_condition]
            if pc_value_type == 'String':
                #*** Can't think of a way it couldn't be a valid
                #*** string???
                pass
            elif pc_value_type == 'PortNumber':
                #*** Check is int 0 < x < 65536:
                if not \
                     self.is_valid_transport_port(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'MACAddress':
                #*** Check is valid MAC address:
                if not self.is_valid_macaddress(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'EtherType':
                #*** Check is valid EtherType - must be two bytes
                #*** as Hex (i.e. 0x0800 is IPv4):
                if not self.is_valid_ethertype(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'IPAddressSpace':
                #*** Check is valid IP address, IPv4 or IPv6, can
                #*** include range or CIDR mask:
                if not self.is_valid_ip_space(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'MatchType':
                #*** Check is valid match type:
                if not pc_value in TC_CONFIG_MATCH_TYPES:
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
                else:
                    #*** Flag that we've seen a match_type so all is good:
                    self.has_match_type = 1
            elif pc_value_type == 'conditions_list':
                #*** Check value is list:
                if not isinstance(pc_value, list):
                    self.logger.critical("A conditions_list clause "
                          "specified but is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
                #*** Now, iterate through conditions list:
                self.logger.debug("Iterating on "
                                    "conditions_list=%s", pc_value)
                for list_item in pc_value:
                    keys = list_item.keys()
                    name = keys[0]
                    self._validate_conditions(list_item[name])
            else:
                #*** Whoops! We have a data type in the policy
                #*** that we've forgot to code a check for...
                self.logger.critical("The following "
                          "PolicyCondition value does not have "
                          "a check: %s, %s", policy_condition, pc_value)
                sys.exit("Exiting nmeta. Coding error "
                                        "in main_policy.yaml file")
        #*** Check match_type attribute present:
        if not self.has_match_type == 1:
            #*** No match_type attribute in stanza:
            self.logger.critical("Missing match_type attribute"
                     " in stanza: %s ", policy_conditions)
            sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
        else:
            #*** Reset to zero as otherwise can break parent evaluations:
            self.has_match_type = 0

    def _optimise(self):
        """
        Return an optimised flow entry match set to install to
        switches based on the TC ruleset passed to it
        """
        opt_rules = []
        #*** Get the tc ruleset name, only one ruleset supported at this stage:
        tc_rules_keys = list(self.tc_policy_yaml['tc_rules'].keys())
        tc_ruleset_name = tc_rules_keys[0]
        self.logger.debug("tc_ruleset_name=%s", tc_ruleset_name)

        #*** Create new variable to reference tc ruleset directly:
        tc_ruleset = self.tc_policy_yaml['tc_rules'][tc_ruleset_name]
        for idx, tc_rule in enumerate(tc_ruleset):
            self.logger.debug("Optimising PolicyRule "
                          "number=%s", idx)
            #*** Optimise the conditions list:
            fe_match_list = \
                        self._opt_conditions_list(tc_rule['conditions_list'])
            #*** Add action(s) to FEs:
            actions = tc_rule['actions']
            fe_match_list = self._add_actions(fe_match_list, actions,
                                    self.tc_policy_yaml)
            #*** Accumulate FEs into result list:
            for flow_entry in fe_match_list:
                opt_rules.append(flow_entry)
        return opt_rules

    def _opt_conditions_list(self, conditions_list):
        """
        Work out how to classify traffic for a list of
        conditions
        .
        Is a Data Plane Auxiliary Engine (DPAE) required to process
        traffic in the flow? (where need to see multiple packets in a
        flow, i.e. statistical or payload types of classification
        """
        fe_match_list = []
        dpae_required = 0
        for condition in conditions_list[0].keys():
            value = conditions_list[0][condition]
            if condition != 'match_type':
                tc_type = self._get_condition_tc_type(condition)
                if tc_type != 'static' and tc_type != 'identity':
                    #*** Record that recourse to DPAE is required
                    dpae_required = 1
                self.logger.debug("      condition=%s value=%s tc_type=%s",
                            condition, value, tc_type)
            else:
                match_type = conditions_list[0]['match_type']
        #*** Check the match type:
        if match_type:
            if match_type == 'any':
                #*** Optimise each individually:
                for condition in conditions_list[0].keys():
                    value = conditions_list[0][condition]
                    #*** Build up FE matches for each condition:
                    if condition != 'match_type':
                        fe_match_list.append \
                                    (self._opt_condition(condition, value))
            elif match_type == 'all':
                #*** Optimise for all:
                if dpae_required == 0:
                    #*** no need for DPAE, so optimise as group for FE rule(s)
                    #*** TBD:
                    pass
                else:
                    #*** Recourse to DPAE required, create a targetted FE
                    #***  with destination of DPAE:
                    #*** TBD:
                    pass
            else:
                self.logger.critical("unknown match type %s", match_type)
                sys.exit("Need to fix match type in policy, exiting...")
        else:
            self.logger.critical("No match type")
            sys.exit("Need to add match type to policy, exiting...")
        return fe_match_list

    def _opt_condition(self, condition, value):
        """
        Passed a single condition and value and return a FE for it
        Result is a dictionary with keys for match, action, instruction
        and flow table (to install rule into)
        """
        flow_entry = {}
        flow_entry['match'] = {}
        flow_entry['action'] = 'none'
        flow_entry['instruction'] = 'none'
        flow_entry['table'] = 'none'
        flow_entry['install_type'] = 'none'
        tc_type = self._get_condition_tc_type(condition)
        flow_entry['condition'] = condition
        flow_entry['value'] = value
        flow_entry['type'] = tc_type
        if tc_type == 'static':
            #*** Return a simple FE match:
            flow_entry['match'][condition] = value
            flow_entry['table'] = 'ft_tt'
            flow_entry['install_type'] = 'immediate'
            return flow_entry
        elif tc_type == 'identity':
            flow_entry['match'][condition] = value
            flow_entry['table'] = 'ft_tt'
            flow_entry['install_type'] = 'on_identity'
            return flow_entry
        elif tc_type == 'payload':
            #*** Return an FE that sends traffic to DPAE:
            flow_entry['match'] = 'any'
            flow_entry['table'] = 'ft_tc'
            flow_entry['action'] = 'parser.OFPActionOutput(dpae_port)'
            flow_entry['instruction'] = 'apply actions, gototable +1'
            flow_entry['install_type'] = 'to_dpae'
            return flow_entry
        elif tc_type == 'statistical':
            #*** Return an FE that sends traffic to DPAE:
            flow_entry['match'] = 'any'
            flow_entry['table'] = 'ft_tc'
            flow_entry['action'] = 'parser.OFPActionOutput(dpae_port)'
            flow_entry['instruction'] = 'apply actions, gototable +1'
            flow_entry['install_type'] = 'to_dpae'
            return flow_entry
        return 0

    def _add_actions(self, fe_match_list, actions, tc_policy_yaml):
        """
        Passed a list of flow entries (FEs) and a set of actions
        and update the FEs with the appropriate actions
        """
        #*** Optimise the action(s) for flow install:
        #***  TBD: this bit done in a hurry, needs work to make more
        #***  extensible
        action = {}
        for action_item in actions:
            if action_item == 'set_qos':
                if actions['set_qos'] in tc_policy_yaml['qos_treatment']:
                    action['Set-Queue'] = \
                            tc_policy_yaml['qos_treatment'][actions['set_qos']]
                else:
                    #*** It's not a defined queue so set by classifier result:
                    action['Set-Queue'] = 'dynamic'
                self.logger.debug("action['Set-Queue']=%s",
                                            action['Set-Queue'])
        #*** Add the action if there isn't already one:
        for flow_entry in fe_match_list:
            if flow_entry['action'] == 'none':
                flow_entry['action'] = action
        return fe_match_list

    def _get_condition_tc_type(self, condition):
        """
        Passed a condition and return the type
        Example: if passed 'eth_type' then return 'static'
        """
        if condition in CONDITION_TYPES:
            return CONDITION_TYPES[condition]
        else:
            self.logger.error("Unknown tc type for condition=%s", condition)
            return "unknown"

    def is_valid_macaddress(self, value_to_check):
        """
        Passed a prospective MAC address and check that
        it is valid.
        Return 1 for is valid IP address and 0 for not valid
        """
        try:
            if not EUI(value_to_check):
                self.logger.debug("Check of "
                        "is_valid_macaddress on %s returned false",
                        value_to_check)
                return 0
        except:
            self.logger.debug("Check of "
                    "is_valid_macaddress on %s raised an exception",
                    value_to_check)
            return 0
        return 1

    def is_valid_ethertype(self, value_to_check):
        """
        Passed a prospective EtherType and check that
        it is valid. Can be hex (0x*) or decimal
        Return 1 for is valid IP address and 0 for not valid
        """
        if value_to_check[:2] == '0x':
            #*** Looks like hex:
            try:
                if not (int(value_to_check, 16) > 0 and \
                               int(value_to_check, 16) < 65536):
                    self.logger.debug("Check of "
                        "is_valid_ethertype as hex on %s returned false",
                        value_to_check)
                    return 0
            except:
                self.logger.debug("Check of "
                    "is_valid_ethertype as hex on %s raised an exception",
                        value_to_check)
                return 0
        else:
            #*** Perhaps it's decimal?
            try:
                if not (int(value_to_check) > 0 and \
                                  int(value_to_check) < 65536):
                    self.logger.debug("Check of "
                        "is_valid_ethertype as decimal on %s returned false",
                        value_to_check)
                    return 0
            except:
                self.logger.debug("Check of "
                    "is_valid_ethertype as decimal on %s raised an exception",
                        value_to_check)
                return 0
        return 1

    def is_valid_ip_space(self, value_to_check):
        """
        Passed a prospective IP address and check that
        it is valid. Can be IPv4 or IPv6 and can be range or have CIDR mask
        Return 1 for is valid IP address and 0 for not valid
        """
        #*** Does it look like a CIDR network?:
        if "/" in value_to_check:
            try:
                if not IPNetwork(value_to_check):
                    self.logger.debug("Network check "
                        "of is_valid_ip_space on %s returned false",
                        value_to_check)
                    return 0
            except:
                self.logger.debug("Network check of "
                    "is_valid_ip_space on %s raised an exception",
                    value_to_check)
                return 0
            return 1
        #*** Does it look like an IP range?:
        elif "-" in value_to_check:
            ip_range = value_to_check.split("-")
            if len(ip_range) != 2:
                self.logger.debug("Range check of "
                    "is_valid_ip_space on %s failed as not 2 items in list",
                    value_to_check)
                return 0
            try:
                if not (IPAddress(ip_range[0]) and IPAddress(ip_range[1])):
                    self.logger.debug("Range check "
                        "of is_valid_ip_space on %s returned false",
                        value_to_check)
                    return 0
            except:
                self.logger.debug("Range check of "
                    "is_valid_ip_space on %s raised an exception",
                    value_to_check)
                return 0
            #*** Check second value in range greater than first value:
            if IPAddress(ip_range[0]).value >= IPAddress(ip_range[1]).value:
                self.logger.debug("Range check of "
                    "is_valid_ip_space on %s failed as range is negative",
                    value_to_check)
                return 0
            #*** Check both IP addresses are the same version:
            if IPAddress(ip_range[0]).version != \
                                 IPAddress(ip_range[1]).version:
                self.logger.debug("Range check of "
                    "is_valid_ip_space on %s failed as IP versions are "
                    "different", value_to_check)
                return 0
            return 1
        else:
            #*** Or is it just a plain simple IP address?:
            try:
                if not IPAddress(value_to_check):
                    self.logger.debug("Check of "
                        "is_valid_ip_space on %s returned false",
                        value_to_check)
                    return 0
            except:
                self.logger.debug("Check of "
                    "is_valid_ip_space on %s raised an exception",
                    value_to_check)
                return 0
        return 1

    def is_valid_transport_port(self, value_to_check):
        """
        Passed a prospective TCP or UDP port number and check that
        it is an integer in the correct range.
        Return 1 for is valid port number and 0 for not valid port
        number
        """
        try:
            if not (int(value_to_check) > 0 and int(value_to_check) < 65536):
                self.logger.debug("Check of "
                    "is_valid_transport_port on %s returned false",
                    value_to_check)
                return 0
        except:
            self.logger.debug("Check of "
                "is_valid_transport_port on %s raised an exception",
                value_to_check)
            return 0
        return 1
