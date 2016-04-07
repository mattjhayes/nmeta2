"""
Nmeta2 main_policy.py Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, in this directory, type in:
    py.test test_main_policy.py
        or just:
    py.test

"""

#*** For tests that need a logger:
import logging
logger = logging.getLogger(__name__)

#*** Testing imports:

import unittest

#*** nmeta2 imports:
import main_policy
import config

#*** Instantiate Config class:
_config = config.Config()

#======================= main_policy.py Unit Tests ============================
policy = main_policy.MainPolicy(_config)

class TestMainPolicy(unittest.TestCase):

    def test_main_policy_tc_policies(self):
        """
        Test main policy tc_policies branch
        """
        tc_policies_good = {'Basic TC Use Case':
                            {'comment': 'Basic TC Use Case',
                            'rule_set': 'tc_ruleset_1',
                            'port_set': 'all_access_ports',
                            'mode': 'active'}}
        # TBD:


    def test_main_policy_tc_rules(self):
        """
        Test main policy tc_rules branch
        """
        tc_rules_good = {'tc_ruleset_1':
                            [{'comment': "blah",
                            'conditions_list': [
                                {'match_type': 'any',
                                 'tcp_src': 123}],
                            'match_type': 'any',
                            'actions': {'set_desc':
                                            'description="foo"'}}]}

        # TBD:


    def test_main_policy_identity(self):
        """
        Test main policy identity branch
        """
        #*** Good and bad identity branches of main policy:
        identity_good1 = {'arp': 1, 'lldp': 1, 'dns': 1, 'dhcp': 1}
        identity_good2 = {'arp': 1, 'lldp': 0, 'dns': 1, 'dhcp': 0}
        identity_bad1 = {'arp': 1, 'lldp': 1, 'dns': 1}
        identity_bad2 = {'arp': 1, 'lldp': 0, 'dns': 1, 'dhcp': 0, 'foo': 1}

        #*** Test the good branches:
        identity = main_policy.Identity(logger, identity_good1)
        assert identity.arp == 1
        assert identity.lldp == 1
        assert identity.dns == 1
        assert identity.dhcp == 1

        identity = main_policy.Identity(logger, identity_good2)
        assert identity.arp == 1
        assert identity.lldp == 0
        assert identity.dns == 1
        assert identity.dhcp == 0

        #*** The bad branches should cause system exit to be raised:
        with self.assertRaises(SystemExit):
            identity = main_policy.Identity(logger, identity_bad1)
        with self.assertRaises(SystemExit):
            identity = main_policy.Identity(logger, identity_bad2)


    def test_main_policy_qos_treatment(self):
        """
        Test main policy qos_treatment branch
        """
        qos_treatment_good = {'low_priority': 3,
                                'high_priority': 2,
                                'constrained_bw': 1,
                                'default_priority': 0}
        # TBD:

    def test_main_policy_port_sets(self):
        """
        Test main policy port_sets branch
        """
        port_sets_good = {'all_access_ports':
                            [{'Switch 1':
                                {'ports': '1-5', 'DPID': 8796748549206}}]}
        # TBD:

    def test_optimise_get_rules(self):
        """
        Test main policy rule optimisation
        """

        #*** Load a policy:
        assert _config.set_value('config_directory', 'config/tests/regression')
        assert _config.set_value('main_policy_filename', 'main_policy_regression_static.yaml')
        policy = main_policy.MainPolicy(_config)
        #*** This is expected optimised rules for above policy:
        good_result = [{'install_type': 'immediate',
                            'instruction': 'none',
                            'value': 1234,
                            'match': {'tcp_src': 1234},
                            'action': {'Set-Queue': 1},
                            'table': 'ft_tt',
                            'type': 'static',
                            'condition': 'tcp_src'},
                            {'install_type': 'immediate',
                            'instruction': 'none',
                            'value': 1234,
                            'match': {'tcp_dst': 1234},
                            'action': {'Set-Queue': 1},
                            'table': 'ft_tt',
                            'type': 'static',
                            'condition': 'tcp_dst'}]
        assert policy.optimised_rules.get_rules() == good_result

        #*** Load a policy:
        assert _config.set_value('config_directory', 'config/tests/regression')
        assert _config.set_value('main_policy_filename', 'main_policy_regression_identity.yaml')
        policy = main_policy.MainPolicy(_config)
        #*** This is expected optimised rules for above policy:
        good_result = [{'install_type': 'on_identity',
                            'instruction': 'none',
                            'value': 'lg.*\\.example\\.com',
                            'match': {'identity_lldp_systemname_re': 'lg.*\\.example\\.com'},
                            'action': {'Set-Queue': 1},
                            'table': 'ft_tt',
                            'type': 'identity',
                            'condition': 'identity_lldp_systemname_re'}]
        assert policy.optimised_rules.get_rules() == good_result

        #*** Load a policy:
        assert _config.set_value('config_directory', 'config/tests/regression')
        assert _config.set_value('main_policy_filename', 'main_policy_regression_statistical.yaml')
        policy = main_policy.MainPolicy(_config)
        #*** This is expected optimised rules for above policy:
        good_result = [{'install_type': 'to_dpae',
                            'instruction': 'apply actions, gototable +1',
                            'value': 'statistical_qos_bandwidth_1',
                            'match': 'any',
                            'action': 'parser.OFPActionOutput(dpae_port)',
                            'table': 'ft_tc',
                            'type': 'statistical',
                            'condition': 'statistical'}]
        assert policy.optimised_rules.get_rules() == good_result

        #*** Load a policy:
        assert _config.set_value('config_directory', 'config/tests/regression')
        assert _config.set_value('main_policy_filename', 'main_policy_dual_classifier.yaml')
        policy = main_policy.MainPolicy(_config)
        #*** This is expected optimised rules for above policy:
        good_result = [{'install_type': 'immediate',
                            'instruction': 'none',
                            'value': 1234,
                            'match': {'tcp_src': 1234},
                            'action': {'Set-Queue': 1},
                            'table': 'ft_tt',
                            'type': 'static',
                            'condition': 'tcp_src'},
                            {'install_type': 'immediate',
                            'instruction': 'none',
                            'value': 1234,
                            'match': {'tcp_dst': 1234},
                            'action': {'Set-Queue': 1},
                            'table': 'ft_tt',
                            'type': 'static',
                            'condition': 'tcp_dst'},
                            {'install_type': 'on_identity',
                            'instruction': 'none',
                            'value': 'pc.*\\.example\\.com',
                            'match': {'identity_lldp_systemname_re': 'pc.*\\.example\\.com'},
                            'action': {'Set-Queue': 1},
                            'table': 'ft_tt',
                            'type': 'identity',
                            'condition': 'identity_lldp_systemname_re'}]
        assert policy.optimised_rules.get_rules() == good_result

#================= Public function tests:

#*** MAC Address Validity Tests:
def test_is_valid_macaddress():
    assert main_policy.is_valid_macaddress(logger, '192.168.3.4') == 0
    assert main_policy.is_valid_macaddress(logger, 'fe80:dead:beef') == 1
    assert main_policy.is_valid_macaddress(logger, 'fe80deadbeef') == 1
    assert main_policy.is_valid_macaddress(logger, 'fe:80:de:ad:be:ef') == 1
    assert main_policy.is_valid_macaddress(logger, 'foo 123') == 0

#*** EtherType Validity Tests:
def test_is_valid_ethertype():
    assert main_policy.is_valid_ethertype(logger, '0x0800') == 1
    assert main_policy.is_valid_ethertype(logger, 'foo') == 0
    assert main_policy.is_valid_ethertype(logger, '0x08001') == 1
    assert main_policy.is_valid_ethertype(logger, '0x18001') == 0
    assert main_policy.is_valid_ethertype(logger, '35020') == 1
    assert main_policy.is_valid_ethertype(logger, '350201') == 0

#*** IP Address Space Validity Tests:
def test_is_valid_ip_space():
    assert main_policy.is_valid_ip_space(logger, '192.168.3.4') == 1
    assert main_policy.is_valid_ip_space(logger, '192.168.3.0/24') == 1
    assert main_policy.is_valid_ip_space(logger, '192.168.322.0/24') == 0
    assert main_policy.is_valid_ip_space(logger, 'foo') == 0
    assert main_policy.is_valid_ip_space(logger, '10.168.3.15/24') == 1
    assert main_policy.is_valid_ip_space(logger, '192.168.3.25-192.168.4.58') == 1
    assert main_policy.is_valid_ip_space(logger, '192.168.4.25-192.168.3.58') == 0
    assert main_policy.is_valid_ip_space(logger, '192.168.3.25-43') == 0
    assert main_policy.is_valid_ip_space(logger, 'fe80::dead:beef') == 1
    assert main_policy.is_valid_ip_space(logger, '10.1.2.2-10.1.2.3') == 1
    assert main_policy.is_valid_ip_space(logger, '10.1.2.3-fe80::dead:beef') == 0
    assert main_policy.is_valid_ip_space(logger, '10.1.2.3-10.1.2.5-10.1.2.8') == 0
    assert main_policy.is_valid_ip_space(logger, 'fe80::dead:beef-fe80::dead:beff') == 1

#*** Transport Port Validity Tests:
def test_is_valid_transport_port_abc123():
    assert main_policy.is_valid_transport_port(logger, 'abc123') == 0
    assert main_policy.is_valid_transport_port(logger, '1') == 1
    assert main_policy.is_valid_transport_port(logger, '65535') == 1
    assert main_policy.is_valid_transport_port(logger, '65536') == 0
