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

#*** Instantiate Config class:
_config = config.Config()

#====================== switch_abstraction.py Unit Tests ======================
#*** Instantiate class:
wsgi_app = WSGIApplication()
nmeta = nmeta2.Nmeta(wsgi=wsgi_app)

switches = switch_abstraction.Switches(nmeta, _config)

sock_mock = mock.Mock()
addr_mock = mock.Mock()

#*** Constant to use for a port not found value:
PORT_NOT_FOUND = 999999999

#*** Test Constants:
MAC123 = '00:00:00:00:01:23'
PORT123 = 123
CONTEXT1 = 1

MAC456 = '00:00:00:00:04:56'
PORT456 = 456
CONTEXT2 = 2

#*** Test Switches and Switch classes that abstract OpenFlow switches:
def test_switches():
    with mock.patch('ryu.controller.controller.Datapath.set_state'):
        #*** Set up fake switch datapaths:
        datapath1 = controller.Datapath(sock_mock, addr_mock)
        datapath1.id = 12345
        datapath2 = controller.Datapath(sock_mock, addr_mock)
        datapath2.id = 67890

        #*** Add switches
        assert switches.add(datapath1) == 1
        assert switches.add(datapath2) == 1

        #*** Look up by DPID:
        assert switches.datapath(datapath1.id) == datapath1
        assert switches.datapath(datapath2.id) == datapath2

        #*** Run function to test single switch use cases:
        _switch_test(switches[datapath1.id])

        #*** Run function to test multiple switch use cases:
        _switches_test(switches[datapath1.id], switches[datapath2.id])


def _switch_test(switch):
    """
    Test cases for a switch
    """
    #*** Add to MAC/port pairs to switch MAC table:
    switch.mactable.add(MAC123, PORT123, CONTEXT1)
    switch.mactable.add(MAC456, PORT456, CONTEXT2)

    #*** Check that we can find mac/in_port:
    assert switch.mactable.mac2port(MAC123, CONTEXT1) == PORT123
    assert switch.mactable.mac2port(MAC456, CONTEXT2) == PORT456

    #*** Check that we can't find mac/in_port:
    assert switch.mactable.mac2port(MAC123, CONTEXT2) == PORT_NOT_FOUND
    assert switch.mactable.mac2port(MAC456, CONTEXT1) == PORT_NOT_FOUND

    #*** Move MAC to another port:
    switch.mactable.add(MAC123, PORT456, CONTEXT1)

    #*** Check MAC is against new port:
    assert switch.mactable.mac2port(MAC123, CONTEXT1) == PORT456

    #*** Check isolation between contexts (same MAC different ports):
    switch.mactable.add(MAC123, PORT123, CONTEXT2)
    assert switch.mactable.mac2port(MAC123, CONTEXT1) == PORT456
    assert switch.mactable.mac2port(MAC123, CONTEXT2) == PORT123

def _switches_test(switch1, switch2):
    """
    Test cases for multiple switches
    """
    #*** Add MAC to each switch:
    #*** Add to MAC/port pairs to switch MAC table:
    switch1.mactable.add(MAC123, PORT123, CONTEXT1)
    switch2.mactable.add(MAC123, PORT456, CONTEXT1)

    #*** Check that we can find mac/in_port:
    assert switch1.mactable.mac2port(MAC123, CONTEXT1) == PORT123
    assert switch2.mactable.mac2port(MAC123, CONTEXT1) == PORT456
