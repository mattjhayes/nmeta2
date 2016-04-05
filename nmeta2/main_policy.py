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

#*** nmeta - Network Metadata - Policy Interpretation Classes and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide network identity and flow metadata.
.
It provides an object for the main policy
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

class MainPolicy(object):
    """
    This class is instantiated by nmeta2.py and provides methods
    to ingest the policy file main_policy.yaml and validate
    that it is correctly structured
    .
    Directly accessible values to read:
        main_policy         # main policy YAML object
        identity.arp        # True if identity arp harvest is enabled
        identity.lldp       # True if identity lldp harvest is enabled
        identity.dns        # True if identity dns harvest is enabled
        identity.dhcp       # True if identity dhcp harvest is enabled
    .
    Methods:
        <TBD>
        tc_policies.*
        tc_rules.*
        identity.*
        qos_treatment.get_policy_qos_treatment_value(key)
        port_sets.get_tc_ports(dpid)

    TBD:
    optimised_rules

    """

    #*** Top level keys that must exist in the main policy:
    TOP_KEYS = ('tc_policies',
                 'tc_rules',
                 'identity',
                 'qos_treatment',
                 'port_sets')

    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('main_policy_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('main_policy_logging_level_c')
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

        #*** Get main policy file information from config:
        config_directory = _config.get_value('config_directory')
        main_policy_filename = _config.get_value('main_policy_filename')

        #*** Ingest main policy from file:
        self.main_policy = self.ingest_policy(config_directory,
                                                main_policy_filename)

        #*** Run a test on the ingested traffic classification policy
        #***  to ensure that it is has the all the right high level keys:
        validate_keys(self.logger, self.main_policy.keys(), self.TOP_KEYS, '.')

        #*** Instantiate classes for the second levels of policy:
        self.tc_policies = \
                       TCPolicies(self.logger, self.main_policy['tc_policies'])
        self.tc_rules = TCRules(self.logger, self.main_policy['tc_rules'])
        self.identity = Identity(self.logger, self.main_policy['identity'])
        self.qos_treatment = \
                   QoSTreatment(self.logger, self.main_policy['qos_treatment'])
        self.port_sets = PortSets(self.logger, self.main_policy['port_sets'])


        #*** Create a set of optimised rules that can be installed onto
        #***  switches from the main policy:
        #self.optimised_rules = self._optimise()
        #self.logger.debug("Optimised rules are %s", self.optimised_rules)

    def ingest_policy(self, config_directory, main_policy_filename):
        """
        Read in main policy from file
        """
        #*** Get working directory:
        working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        fullpathname = os.path.join(working_directory,
                                         config_directory,
                                         main_policy_filename)
        self.logger.info("About to open config file=%s", fullpathname)
        #*** Ingest the policy file:
        try:
            with open(fullpathname, 'r') as filename:
                _main_policy = yaml.load(filename)
        except (IOError, OSError) as exception:
            self.logger.error("Failed to open policy "
                              "file=%s exception=%s",
                              fullpathname, exception)
            sys.exit("Exiting nmeta. Please create traffic classification "
                             "policy file")

        return _main_policy

class TCPolicies(object):
    """
    Represents the portion of main policy off the root key 'tc_policies'
    """

    def __init__(self, logger, policy):
        self.logger = logger

class TCRules(object):
    """
    Represents the portion of main policy off the root key 'tc_rules'
    """

    def __init__(self, logger, policy):
        self.logger = logger
        self.policy = policy

        #*** Get the tc ruleset name, only one ruleset supported at this stage:
        tc_rules_keys = list(self.policy.keys())
        if not len(tc_rules_keys) == 1:
            #*** Unsupported number of rulesets so log and exit:
            self.logger.critical("Unsupported "
                                    "number of tc rulesets. Should be 1 but "
                                    "is %s", len(tc_rules_keys))
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        self.tc_ruleset_name = tc_rules_keys[0]
        self.logger.debug("tc_ruleset_name=%s",
                              self.tc_ruleset_name)

        #*** Instantiate the rules as class objects:
        self.tc_rules = []
        for idx, tc_rule in enumerate(self.policy[self.tc_ruleset_name]):
            self.logger.debug("Validating TC rule "
                              "number=%s rule=%s", idx, tc_rule)
            self.tc_rules.append(TCRule(self.logger, tc_rule))

class TCRule(object):
    """
    Represents a TC rule
    """

    TC_RULE_ATTRIBUTES = ('comment',
                            'match_type',
                            'conditions_list',
                            'actions')

    def __init__(self, logger, rule):
        self.logger = logger
        self.rule = rule

        #*** Validate the correct keys exist in this TC rule:
        validate_keys(self.logger, rule.keys(), self.TC_RULE_ATTRIBUTES,
                                                    'tc_rules.ruleset.rule')

class Identity(object):
    """
    Represents the portion of main policy off the root key 'identity'
    """
    #*** Keys that must exist under 'identity' in the policy:
    IDENTITY_KEYS = ('arp',
                    'lldp',
                    'dns',
                    'dhcp')

    def __init__(self, logger, policy):
        self.logger = logger
        self.policy = policy
        #*** Validate the correct keys exist in this branch of main policy:
        validate_keys(self.logger, policy.keys(), self.IDENTITY_KEYS,
                                                               'identity')
        self.arp = policy['arp']
        self.lldp = policy['lldp']
        self.dns = policy['dns']
        self.dhcp = policy['dhcp']

class QoSTreatment(object):
    """
    Represents the portion of main policy off the root key 'qos_treatment'
    """
    #*** Keys that must exist under 'qos_treatment' in the policy:
    QOS_TREATMENT_KEYS = ('default_priority',
                        'constrained_bw',
                        'high_priority',
                        'low_priority')

    def __init__(self, logger, policy):
        self.logger = logger
        self.policy = policy
        #*** Validate the correct keys exist in this branch of main policy:
        validate_keys(self.logger, policy.keys(), self.QOS_TREATMENT_KEYS,
                                                               'qos_treatment')

    def get_policy_qos_treatment_value(self, qos_key):
        """
        Return a value for a given key under the 'qos_treatment' root of
        the policy
        """
        if not qos_key in self.QOS_TREATMENT_KEYS:
            self.logger.error("The qos_treatment key %s is not valid", qos_key)
            return 0
        return self.policy[qos_key]

class PortSets(object):
    """
    Represents the portion of main policy off the root key 'port_sets'
    """

    def __init__(self, logger, policy):
        self.logger = logger
        self.policy = policy

    def get_tc_ports(self, dpid):
        """
        Passed a DPID and return a tuple of port numbers on which to
        run TC on that switch, or 0 if none
        """
        #*** TBD, this is hardcoded to this name, needs fixing:
        port_set = self.policy['all_access_ports']

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


def validate_keys(logger, keys, schema, branch):
    """
    Validate a set of keys against a schema tuple to ensure that
    there are no missing or extraneous keys
    """
    #*** validate that all required keys exist:
    for key in keys:
        if not key in schema:
            logger.critical("Missing key % in main policy branch %s",
                                        key, branch)
            sys.exit("Exiting nmeta. Please fix error in main_policy.yaml")
    #*** Conversely, check all keys are valid:
    for key in schema:
        if not key in keys:
            logger.critical("Invalid key %s in level %s of main policy",
                                        key, branch)
            sys.exit("Exiting nmeta. Please fix error in main_policy.yaml")
    return 1
