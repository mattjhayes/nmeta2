"""
Nmeta2 Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test tests_unit.py

"""

#*** Handle tests being in different directory branch to app code:
import sys

sys.path.insert(0, '../nmeta2')

#*** For tests that need a logger:
import logging
logger = logging.getLogger(__name__)

#*** Testing imports:
import mock
import unittest

#*** Ryu imports:
from ryu.base import app_manager  # To suppress cyclic import
from ryu.controller import controller
from ryu.controller import handler
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_0_parser
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.app.wsgi import route

#*** JSON imports:
import json
from json import JSONEncoder

#*** nmeta2 imports:
import nmeta2
import switch_abstraction
import config
import api
import main_policy

#*** Instantiate Config class:
_config = config.Config()

#====================== switch_abstraction.py Unit Tests ======================
#*** Instantiate class:
wsgi_app = WSGIApplication()
nmeta = nmeta2.Nmeta(wsgi=wsgi_app)

switches = switch_abstraction.Switches(nmeta, _config)

sock_mock = mock.Mock()
addr_mock = mock.Mock()


#*** Test Switches and Switch classes that abstract OpenFlow switches:
def test_switches():
    with mock.patch('ryu.controller.controller.Datapath.set_state'):
        #*** Set up a fake switch datapath:
        datapath = controller.Datapath(sock_mock, addr_mock)

        #*** Add a switch
        assert switches.add(datapath) == 1

        #*** Look up by DPID:
        assert switches.datapath(datapath.id) == datapath

        _switch_test(switches[datapath.id])

def _switch_test(switch):
    """
    Test cases for a switch
    """
    #*** Constant to use for a port not found value:
    PORT_NOT_FOUND = 999999999

    #*** Test values:
    mac123 = '00:00:00:00:01:23'
    port123 = 123
    context1 = 1

    mac456 = '00:00:00:00:04:56'
    port456 = 456
    context2 = 2

    #*** Add to MAC/port pairs to switch MAC table:
    switch.mactable.add(mac123, port123, context1)
    switch.mactable.add(mac456, port456, context2)

    #*** Check that we can find mac/in_port:
    assert switch.mactable.mac2port(mac123, context1) == port123
    assert switch.mactable.mac2port(mac456, context2) == port456

    #*** Check that we can't find mac/in_port:
    assert switch.mactable.mac2port(mac123, context2) == PORT_NOT_FOUND
    assert switch.mactable.mac2port(mac456, context1) == PORT_NOT_FOUND

#============================ api.py Unit Tests ===============================

class _TestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(_TestController, self).__init__(req, link, data, **config)
        eq_(data['test_param'], 'foo')

class Test_wsgi(unittest.TestCase):
    """
    Test case for running WSGI controller for API testing
    """
    def setUp(self):
        wsgi = WSGIApplication()
        #*** Instantiate API class:
        self.api = api.Api(self, _config, wsgi)

def test_decode_JSON():
    #*** The JSON_Body class is in the api.py module. Good JSON:
    good_json = '{\"foo\": \"123\"}'
    good = api.JSON_Body(good_json)
    assert not good.error
    assert good.error == ""
    assert good.json == {'foo': '123'}
    assert good['foo'] == '123'
    assert good['bar'] == 0

    #*** Bad JSON:
    bad_json = "foo, bar=99"
    bad = api.JSON_Body(bad_json)
    assert bad.json == {}
    assert bad.error == '{\"Error\": \"Bad JSON\"}'

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
        Test main policy tc_rules branch
        """
        qos_treatment_good = {'low_priority': 3,
                                'high_priority': 2,
                                'constrained_bw': 1,
                                'default_priority': 0}
        # TBD:

    def test_main_policy_port_sets(self):
        """
        Test main policy tc_rules branch
        """
        port_sets_good = {'all_access_ports':
                            [{'Switch 1':
                                {'ports': '1-5', 'DPID': 8796748549206}}]}
        # TBD:

