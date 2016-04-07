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


