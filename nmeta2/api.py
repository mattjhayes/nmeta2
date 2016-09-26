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

#*** nmeta2 - Network Metadata - REST API Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide network identity and flow metadata.
.
It provides methods for RESTful API connectivity.
"""

import logging
import logging.handlers
import socket
import time
import sys

#*** Ryu Imports:
from ryu.exception import RyuException
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

#*** Web API REST imports:
from webob import Response
import json
from json import JSONEncoder

#*** Universal Unique Identifier:
import uuid
from uuid import UUID

#*** Constants for REST API:
REST_RESULT = 'result'
REST_NG = 'failure'
REST_DETAILS = 'details'
NMETA_INSTANCE = 'nmeta_api_app'
LOGGER = 'logger_api_app'

# REST command template
def rest_command(func):
    """
    REST API command template
    """
    def _rest_command(*args, **kwargs):
        """
        Run a REST command and return
        appropriate response.
        Keys/Values returned to this wrapper in a dictionary.
        Valid Keys are:
            'msg': the data to return in the message body
            'location': a new location for the resource
            'status': HTTP status code to return
        """
        result = dict()
        try:
            result = func(*args, **kwargs)
        except SyntaxError as e:
            status = 400
            details = e.msg
            print "ERROR: SyntaxError in _rest_command, status ", status, \
                                    "msg ", details
            msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
            return Response(status=status, body=json.dumps(msg))
        except (ValueError, NameError) as e:
            status = 400
            details = e.message
            print "ERROR: ValueError or NameError in _rest_command, status ", \
                                    status, "msg ", details
            msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
            return Response(status=status, body=json.dumps(msg))
        except NotFoundError as msg:
            status = 404
            details = str(msg)
            print "ERROR: NotFoundError in _rest_command, status ", status, \
                                    "msg ", details
            msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
            return Response(status=status, body=json.dumps(msg))
        except:
            #*** General exception handling...
            exc_type, exc_value, exc_traceback = sys.exc_info()
            status = 500
            details = "exc_type=" + str(exc_type) + " exc_value=" + \
                        str(exc_value) + " exc_traceback=" + \
                        str(exc_traceback)
            print "ERROR: NotFoundError in _rest_command, status ", status, \
                                    "msg ", details
            msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
            return Response(status=status, body=json.dumps(msg))
        if 'location' in result:
            #*** Return an HTTP 201 with location for new resource:
            msg = result['msg']
            res_link = result['location']
            status = 201
            return Response(status=status, content_type='application/json',
                            location=res_link, body=json.dumps(msg))
        else:
            #*** No location to return:
            msg = result['msg']
            if 'status' in result:
                status = result['status']
            else:
                status = 200
            return Response(status=status, content_type='application/json',
                            body=json.dumps(msg))

    #*** Return the inner function:
    return _rest_command

class NotFoundError(RyuException):
    message = 'Error occurred talking to function <TBD>'

class RESTAPIController(ControllerBase):
    """
    This class is used to control REST API access to the
    nmeta data and control functions
    """
    def __init__(self, req, link, data, **config):
        super(RESTAPIController, self).__init__(req, link, data, **config)
        self.nmeta_parent_self = data[NMETA_INSTANCE]
        #*** Get the parent logger and log against that:
        self.logger = data[LOGGER]
        #*** Performance Note: this init gets run for every API call...
        #*** Update JSON to support UUID encoding:
        JSONEncoder_olddefault = JSONEncoder.default
        def JSONEncoder_newdefault(self, o):
            if isinstance(o, UUID):
                return str(o)
            return JSONEncoder_olddefault(self, o)
        JSONEncoder.default = JSONEncoder_newdefault


    @rest_command
    def rest_dpae_create(self, req, **kwargs):
        """
        REST API function that creates a DPAE resource (Phase 1)
        (HTTP POST method)
        """
        nmeta = self.nmeta_parent_self
        #*** Decode request body as JSON:
        dpae_req_body = JSON_Body(req.body)
        if dpae_req_body.error:
            return ({'status': 400, 'msg': dpae_req_body.error})
        self.logger.info("Phase 1 DPAE initiate request body=%s",
                                    dpae_req_body.json)

        #*** Validate required keys are present in JSON:
        if not dpae_req_body.validate(['hostname_dpae', 'if_name',
                        'uuid_dpae']):
            self.logger.error("Validation error %s", dpae_req_body.error)
            return ({'status': 400, 'msg': dpae_req_body.error})
        hostname_dpae = dpae_req_body['hostname_dpae']
        uuid_dpae = dpae_req_body['uuid_dpae']
        if_name = dpae_req_body['if_name']

        #*** Create a unique ID:
        hostname = socket.getfqdn()
        our_uuid = uuid.uuid1()

        #*** Record in database with controller UUID as key:
        db_data = {'_id': str(our_uuid), 'time_created': time.time(),
                    'hostname_dpae': hostname_dpae, 'uuid_dpae': uuid_dpae,
                    'if_name': if_name}
        db_result = nmeta.dbdpae.insert_one(db_data)
        self.logger.info("Phase 1 created new db record id=%s",
                            db_result.inserted_id)

        #*** Get the MAC addresses and ethertype for the DPAE to send to
        #***  in Phase2:
        dpae2ctrl_mac = str(nmeta.dpae2ctrl_mac)
        ctrl2dpae_mac = str(nmeta.ctrl2dpae_mac)
        dpae_ethertype = int(nmeta.dpae_ethertype)

        #*** Create JSON response body:
        json_create_response = json.dumps({'hostname_controller': hostname,
                                    'uuid_dpae': uuid_dpae,
                                    'uuid_controller': our_uuid,
                                    'dpae2ctrl_mac': dpae2ctrl_mac,
                                    'ctrl2dpae_mac': ctrl2dpae_mac,
                                    'dpae_ethertype': dpae_ethertype}
                                    )
        self.logger.info("Phase 1 DPAE join response body=%s",
                                        json_create_response)

        #*** Return response body for sending to DPAE
        #***  Include the location, which is branch where resource is created:
        result = {'msg': json_create_response, 'location': str(our_uuid)}
        return result

    @rest_command
    def rest_dpae_read(self, req, **kwargs):
        """
        REST API function that returns DPAE resource names
        (HTTP GET method)
        """
        #*** We don't support this, so return a 403 Forbidden:
        return ({'status': 403,
                'msg': '{\"Error\": \"Listing of all DPAE is forbidden\"}'})

    @rest_command
    def rest_dpae_read_uuid(self, req, uri_uuid, **kwargs):
        """
        REST API function that returns attributes of a DPAE resource
        (HTTP GET method) for Phase 2
        """
        nmeta = self.nmeta_parent_self
        _results = {}
        i = 0
        #*** Decode request body as JSON:
        dpae_req_body = JSON_Body(req.body)
        if dpae_req_body.error:
            return ({'status': 400, 'msg': dpae_req_body.error})
        self.logger.info("Phase 2 DPAE read request body=%s",
                                    dpae_req_body.json)

        #*** Validate required keys are present in JSON:
        if not dpae_req_body.validate(['hostname_dpae', 'if_name', 'uuid_dpae',
                    'uuid_controller']):
            self.logger.error("Validation error %s", dpae_req_body.error)
            return ({'status': 400, 'msg': dpae_req_body.error})
        hostname_dpae = dpae_req_body['hostname_dpae']
        uuid_dpae = dpae_req_body['uuid_dpae']
        if_name = dpae_req_body['if_name']
        uuid_controller = dpae_req_body['uuid_controller']

        #*** Check that the UUID we were passed in the URI is valid:
        try:
            val = UUID(uri_uuid, version=1)
        except ValueError:
            return ({'status': 400, 'msg': '{\"Error\": \"Bad UUID in URI\"}'})

        #*** Look up the UUID in the database:
        db_result = nmeta.dbdpae.find_one({'_id': str(uri_uuid)})
        if not db_result:
            #*** Not in database:
            return ({'status': 400, 'msg': '{\"Error\": \"UUID not in DB\"}'})

        #*** Validate that parameters in HTTP GET JSON match DB:
        if not hostname_dpae == str(db_result[u'hostname_dpae']):
            return ({'status': 400, 'msg': \
                      '{\"Error\": \"hostname_dpae mismatch with DB value\"}'})
        if not uuid_dpae == str(db_result[u'uuid_dpae']):
            return ({'status': 400, 'msg': \
                      '{\"Error\": \"uuid_dpae mismatch with DB value\"}'})
        if not uuid_controller == str(db_result['_id']):
            return ({'status': 400, 'msg': \
                    '{\"Error\": \"uuid_controller mismatch with DB value\"}'})
        if not if_name == str(db_result[u'if_name']):
            return ({'status': 400, 'msg': \
                    '{\"Error\": \"if_name mismatch with DB value\"}'})

        #*** Just return fields from DB doc that we want to return:
        if 'hostname_dpae' in db_result:
            _results['hostname_dpae'] = db_result[u'hostname_dpae']
        if 'uuid_dpae' in db_result:
            _results['uuid_dpae'] = db_result[u'uuid_dpae']
        if 'uuid_controller' in db_result:
            _results['uuid_controller'] = db_result[u'uuid_controller']
        if 'time_created' in db_result:
            _results['time_created'] = db_result[u'time_created']
        if 'dpid' in db_result:
            _results['dpid'] = db_result[u'dpid']
        if 'switch_port' in db_result:
            _results['switch_port'] = db_result[u'switch_port']
        if 'lastModified' in db_result:
            _results['lastModified'] = db_result[u'lastModified']

        #*** Serialise JSON response body:
        json_read_response = json.dumps(_results)
        self.logger.info("DPAE Read response body=%s",
                                        json_read_response)

        #*** Return response body for sending to DPAE:
        result = {'msg': json_read_response}
        return result

    @rest_command
    def rest_dpae_keepalive(self, req, uri_uuid, **kwargs):
        """
        REST API function that updates attributes of a DPAE resource
        (HTTP PUT method). Body must include uuid_dpae corresponding
        to a current uuid_controller (in URI).
        Used by DPAE for keepalive messages.
        """
        nmeta = self.nmeta_parent_self
        _results = {}
        i = 0
        #*** Decode request body as JSON:
        dpae_req_body = JSON_Body(req.body)
        if dpae_req_body.error:
            return ({'status': 400, 'msg': dpae_req_body.error})
        #*** Validate required keys are present in JSON:
        if not dpae_req_body.validate(['uuid_dpae',
                    'uuid_controller', 'keepalive', 'if_name']):
            self.logger.error("Validation error %s", dpae_req_body.error)
            return ({'status': 400, 'msg': dpae_req_body.error})

        #*** Look up DB record for this DPAE:
        uuid_dpae = dpae_req_body['uuid_dpae']
        if uuid_dpae:
            cursor = nmeta.dbdpae.find({'uuid_dpae': uuid_dpae})
            if not cursor:
                #*** Couldn't find in database so exit:
                self.logger.error("DPAE update request no db doc uuid_dpae=%s"
                                    ", exiting")
                return ({'status': 400, 'msg': '{\"Error\": \"Not in DB\"}'})
        else:
            #*** We weren't passed a uuid_dpae field so exit:
            self.logger.error("DPAE update request no uuid_dpae, exiting")
            return ({'status': 400, 'msg': '{\"Error\": \"No uuid_dpae\"}'})

        #*** Update database record for this DPAE with keepalive lastseen time:
        uuid_controller = dpae_req_body['uuid_controller']
        db_result = nmeta.dbdpae.update_one(
                        {'_id': str(uuid_controller)},
                        {
                            '$set': {
                                'last_seen': time.time()
                            },
                        }
                    )
        if db_result.matched_count != 1:
            return ({'status': 400, 'msg': '{\"Error\": \"UUID not in DB\"}'})

        #*** Return response body for sending to DPAE:
        result = {'msg': 'Okay, got that'}
        return result

    @rest_command
    def rest_dpae_delete(self, req, **kwargs):
        """
        REST API function that deletes a DPAE resource
        (HTTP DELETE method)
        """
        #*** TBD
        print "In rest_dpae_delete"

    @rest_command
    def rest_dpae_send_sniff_conf_pkt(self, req, uri_uuid, **kwargs):
        """
        REST API function that returns attributes of a DPAE resource
        (HTTP GET method)
        """
        nmeta = self.nmeta_parent_self
        _results = {}
        i = 0
        #*** Decode request body as JSON:
        dpae_req_body = JSON_Body(req.body)
        if dpae_req_body.error:
            return ({'status': 400, 'msg': dpae_req_body.error})
        self.logger.debug("DPAE send sniff conf pkt request body=%s",
                                    dpae_req_body.json)
        #*** Validate required keys are present in JSON:
        if not dpae_req_body.validate(['hostname_dpae', 'if_name', 'uuid_dpae',
                    'uuid_controller']):
            self.logger.error("Validation error %s", dpae_req_body.error)
            return ({'status': 400, 'msg': dpae_req_body.error})

        #*** Check that the UUID we were passed in the URI is valid:
        try:
            val = UUID(uri_uuid, version=1)
        except ValueError:
            return ({'status': 400, 'msg': '{\"Error\": \"Bad UUID in URI\"}'})
        #*** Check the Controller UUID on the URI matches the one in JSON body:
        if uri_uuid != dpae_req_body['uuid_controller']:
            return ({'status': 400, 'msg': '{\"Error\": \"UUID mismatch\"}'})

        #*** Look up the UUID in the database:
        db_result = nmeta.dbdpae.find_one({'_id': str(uri_uuid)})
        if not db_result:
            #*** Not in database:
            return ({'status': 400, 'msg': '{\"Error\": \"UUID not in DB\"}'})

        #*** Validate and retrieve fields from database:
        #*** Get datapath for switch:
        if 'dpid' in db_result:
            dpid = db_result[u'dpid']
        else:
            return ({'status': 500, 'msg': '{\"Error\": \"no datapath\"}'})

        #*** Retrieve datapath object
        datapath = nmeta.switches.datapath(dpid)
        if not datapath:
            return ({'status': 500, 'msg': '{\"Error\": \"no dpid stored\"}'})

        #*** Get switch port to send packet out:
        if 'switch_port' in db_result:
            out_port = db_result[u'switch_port']
        else:
            return ({'status': 500, 'msg': '{\"Error\": \"no switch port\"}'})

        #*** Since packet didn't come in a port we set source as controller:
        in_port = datapath.ofproto.OFPP_CONTROLLER

        #*** Get packet header parameters to use from nmeta configuration:
        dpae2ctrl_mac = str(nmeta.dpae2ctrl_mac)
        ctrl2dpae_mac = str(nmeta.ctrl2dpae_mac)
        dpae_ethertype = int(nmeta.dpae_ethertype)

        #*** Create sniff confirmation packet:
        e = ethernet.ethernet(dst=ctrl2dpae_mac,
                      src=dpae2ctrl_mac,
                      ethertype=dpae_ethertype)
        p = packet.Packet()
        p.add_protocol(e)
        #*** Serialise JSON response body:
        packet_payload_json = json.dumps({
                    'uuid_controller': dpae_req_body['uuid_controller'],
                    'hostname_dpae': dpae_req_body['hostname_dpae'],
                    'if_name': dpae_req_body['if_name'],
                    'uuid_dpae': dpae_req_body['uuid_dpae']})
        p.add_protocol(packet_payload_json)
        p.serialize()
        data = p.data

        #*** Send confirmation packet, no queueing:
        switch = nmeta.switches[dpid]
        packet_out_result = switch.packet_out(data, in_port, out_port, 0, 1)

        #*** Check packet send result:
        if not packet_out_result:
            #*** Failed to send packet for some reason:
            return ({'status': 500, 'msg': '{\"Error\": \"Pkt send failed\"}'})
        else:
            #*** Return confirmation that we sent packet via API:
            result = {'msg': 'Phase3 Sniff conf packet sent'}
            return result

    @rest_command
    def rest_dpae_tc_state_update(self, req, uri_uuid, **kwargs):
        """
        REST API function that sets DPAE interface TC state
        (HTTP PUT method)
        """
        nmeta = self.nmeta_parent_self
        #*** Decode request body as JSON:
        dpae_req_body = JSON_Body(req.body)
        if dpae_req_body.error:
            return ({'status': 400, 'msg': dpae_req_body.error})

        self.logger.debug("DPAE TC State update request body=%s",
                                    dpae_req_body.json)

        #*** Validate required keys are present in JSON:
        if not dpae_req_body.validate(['tc_state', 'dpae_version', 'uuid_dpae',
                    'uuid_controller']):
            self.logger.error("Validation error %s", dpae_req_body.error)
            return ({'status': 400, 'msg': dpae_req_body.error})

        #*** Check version compatibility:
        if not version_compare(dpae_req_body['dpae_version'],
                                                                nmeta.version):
            self.logger.warning("Possible version compatibility issue. "
                        "DPAE_version=%s nmeta2_version=%s",
                        dpae_req_body['dpae_version'], nmeta.version)

        #*** Check what state is being set (we only support 'run'):
        tc_state = dpae_req_body['tc_state']
        if tc_state:
            if tc_state == 'run':
                self.logger.debug("DPAE requested TC state=%s", tc_state)
            else:
                self.logger.error("DPAE TC unsupported state=%s", tc_state)
                return ({'status': 400, 'msg': '{\"Error\": \"No tc_state\"}'})
        else:
            self.logger.error("DPAE did not send tc_state")
            return ({'status': 400, 'msg': '{\"Error\": \"No tc_state\"}'})

        #*** Check that the UUID we were passed in the URI is valid:
        try:
            val = UUID(uri_uuid, version=1)
        except ValueError:
            return ({'status': 400, 'msg': '{\"Error\": \"Bad UUID in URI\"}'})

        #*** Look up the UUID in the database:
        db_result = nmeta.dbdpae.find_one({'_id': str(uri_uuid)})
        if not db_result:
            #*** Not in database:
            return ({'status': 400, 'msg': '{\"Error\": \"UUID not in DB\"}'})

        #*** Validate and retrieve fields from database:
        #*** Get datapath for switch:
        if 'dpid' in db_result:
            dpid = db_result[u'dpid']
        else:
            return ({'status': 500, 'msg': '{\"Error\": \"no datapath\"}'})

        #*** Retrieve datapath object
        datapath = nmeta.switches.datapath(dpid)
        if not datapath:
            return ({'status': 500, 'msg': '{\"Error\": \"no dpid stored\"}'})

        #*** Get switch port to send packets out:
        if 'switch_port' in db_result:
            out_port = db_result[u'switch_port']
        else:
            return ({'status': 500, 'msg': '{\"Error\": \"no switch port\"}'})

        #*** Call function to set up switch to DPAE FE:
        _results = nmeta.tc_start(datapath, out_port)

        #*** Add the uuid_dpae to the response:
        _results['uuid_dpae'] = dpae_req_body['uuid_dpae']

        #*** Encode response as JSON and send to DPAE:
        json_response = json.dumps(_results)
        self.logger.debug("json_response=%s", json_response)
        _results_dict = {'msg': json_response}
        return _results_dict

    @rest_command
    def rest_dpae_main_policy_read(self, req, uri_uuid, **kwargs):
        """
        REST API function that retrieves main policy (for a DPAE)
        (HTTP GET method)
        """
        nmeta = self.nmeta_parent_self
        _results = nmeta.main_policy.main_policy
        _results_dict = {'msg': _results}
        return _results_dict

    @rest_command
    def rest_dpae_tc_opt_rules_read(self, req, uri_uuid, **kwargs):
        """
        REST API function that retrieves TC optimised rules (for a DPAE)
        (HTTP GET method)
        """
        nmeta = self.nmeta_parent_self
        _results = nmeta.main_policy.optimised_rules.get_rules()
        _results_dict = {'msg': _results}
        return _results_dict

    @rest_command
    def rest_dpae_tc_classify_advice(self, req, uri_uuid, **kwargs):
        """
        REST API function for a DPAE to inform Controller of a
        traffic classification that it has determined
        (HTTP POST method)
        """
        nmeta = self.nmeta_parent_self
        #*** Decode request body as JSON:
        dpae_req_body = JSON_Body(req.body)
        if dpae_req_body.error:
            return ({'status': 400, 'msg': dpae_req_body.error})
        self.logger.debug("TC advice body=%s",
                                    dpae_req_body.json)

        #*** Validate required keys are present in JSON:
        if not dpae_req_body.validate(['type',
                    'subtype']):
            self.logger.error("Validation error %s", dpae_req_body.error)
            return ({'status': 400, 'msg': dpae_req_body.error})

        tc_type = dpae_req_body[u'type']
        tc_subtype = dpae_req_body[u'subtype']

        #*** Look up the UUID in the database:
        db_result = nmeta.dbdpae.find_one({'_id': str(uri_uuid)})
        if not db_result:
            #*** Not in database:
            return ({'status': 400, 'msg': '{\"Error\": \"UUID not in DB\"}'})
        #*** Retrieve the datapath for this switch from the database:
        if 'dpid' in db_result:
            dpid = db_result[u'dpid']
        else:
            return ({'status': 500, 'msg': '{\"Error\": \"no dpid\"}'})

        if tc_type == 'id':
            #*** Identity Metadata. Get fields out and update ID database:
            if not dpae_req_body.validate(['src_mac', 'detail1']):
                self.logger.error("Validation error %s", dpae_req_body.error)
                return ({'status': 400, 'msg': dpae_req_body.error})
            src_mac = dpae_req_body[u'src_mac']
            detail1 = dpae_req_body[u'detail1']
            #*** Call a function to process the identity classification
            #***  advice:
            nmeta.tc_advice_id(dpid, tc_type, tc_subtype, src_mac, detail1)

        elif tc_type == 'treatment+suppress' or tc_type == 'suppress' \
                    or tc_type == 'treatment':
            #*** Validate fields exist and extract:
            flow_dict = {}
            if not dpae_req_body.validate(['ip_A', 'ip_B', 'proto', 'tp_A',
                                                'tp_B', 'flow_packets',
                                                'actions']):
                self.logger.error("Validation error %s", dpae_req_body.error)
                return ({'status': 400, 'msg': dpae_req_body.error})
            flow_dict['ip_A'] = dpae_req_body[u'ip_A']
            flow_dict['ip_B'] = dpae_req_body[u'ip_B']
            flow_dict['proto'] = dpae_req_body[u'proto']
            flow_dict['tp_A'] = dpae_req_body[u'tp_A']
            flow_dict['tp_B'] = dpae_req_body[u'tp_B']
            flow_dict['actions'] = dpae_req_body[u'actions']
            if dpae_req_body.validate(['qos_treatment']):
                flow_dict['qos_treatment'] = dpae_req_body[u'qos_treatment']

            if tc_type == 'treatment+suppress' or tc_type == 'suppress':
                #*** Do flow suppression.
                self.logger.debug("DPAE flow suppression type=%s "
                            "packets_seen=%s",
                            tc_type, dpae_req_body[u'flow_packets'])
                nmeta.switches[dpid].flowtables.add_fe_tcf_suppress(flow_dict)

            if tc_type == 'treatment+suppress' or tc_type == 'treatment':
                #*** Do traffic treatment.
                self.logger.debug("Traffic treatment type=%s "
                            "packets_seen=%s",
                            tc_type, dpae_req_body[u'flow_packets'])
                nmeta.switches[dpid].flowtables.add_fe_tt_advised(flow_dict)

        else:
            self.logger.info("Didn't action tc_type=%s", tc_type)

        result = {'msg': 'Thanks for letting us know!'}
        return result

    @rest_command
    def rest_idmac_read(self, req, **kwargs):
        """
        REST API function that returns Identity (MAC) resource
        (HTTP GET method)
        """
        nmeta = self.nmeta_parent_self
        _results = {}
        i = 0
        #*** Retrieve all records:
        cursor = nmeta.dbidmac.find()
        for document in cursor:
            _results[i] = {}
            _results[i]['dpid'] = document[u'dpid']
            _results[i]['mac'] = document[u'mac']
            _results[i]['port'] = document[u'port']
            i += 1
        result = {'msg': _results}
        return result

class JSON_Body(object):
    """
    Represents a JSON-encoded body of an HTTP request.
    Doesn't do logging, but does set .error when things
    don't go to plan with a friendly message.
    """
    def __init__(self, req_body):
        self.json = {}
        self.error = ""
        self.error_full = ""
        self.req_body = self.decode(req_body)

    def decode(self, req_body):
        """
        Passed an allegedly JSON body and see if it
        decodes. Set error variable for exceptions
        """
        json_decode = {}
        if req_body:
            #*** Try decode as JSON:
            try:
                json_decode = json.loads(req_body)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.error = '{\"Error\": \"Bad JSON\"}'
                self.error_full = '{\"Error\": \"Bad JSON\",' + \
                             '\"exc_type\":' + str(exc_type) + ',' + \
                             '\"exc_value\":' + str(exc_value) + ',' + \
                             '\"exc_traceback\":' + str(exc_traceback) + '}'
                return 0
        else:
            json_decode = {}
        self.json = json_decode
        return json_decode

    def validate(self, key_list):
        """
        Passed a list of keys and check that they exist in the
        JSON. If they don't return 0 and set error to description
        of first missing key that was found
        """
        for key in key_list:
            if not key in self.req_body:
                self.error = '{\"Error\": \"No ' + key + '\"}'
                return 0
        return 1

    def __getitem__(self, key):
        """
        Passed a key and see if it exists in JSON
        object. If it does, return the value for the key.
        If not, return 0
        Example:
            foo = json_body['foo']
        """
        if key in self.req_body:
            return self.req_body[key]
        else:
            return 0

def version_compare(version1, version2):
    """
    Compare two semantic version numbers and return 1 if they
    are the same major version number
    """
    (major1, minor1, patch1) = version1.split('.')
    (major2, minor2, patch2) = version1.split('.')
    if major1 == major2:
        return 1
    else:
        return 0

class Api(object):
    """
    This class is instantiated by nmeta.py and provides methods
    for RESTful API connectivity.
    """
    #*** URLs for REST API:
    url_dpae_base = '/nmeta/v2/aux/'
    url_dpae_uuid = url_dpae_base + '{uri_uuid}'
    url_dpae_uuid_sendconfpkt = url_dpae_uuid + '/send_conf_packet/'
    url_dpae_uuid_tc_state = url_dpae_uuid + '/services/tc/state/'
    url_dpae_uuid_main_policy = url_dpae_uuid + '/main_policy/'
    url_dpae_uuid_tc_opt_rules = url_dpae_uuid + '/services/tc/opt_rules/'
    url_dpae_uuid_tc_classify = url_dpae_uuid + '/services/tc/classify/'
    url_dpae_uuid_keepalive = url_dpae_uuid + '/keepalive/'

    url_idmac = '/nmeta/v2/id/mac/'
    IP_PATTERN = r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$){4}\b'
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, _nmeta, _config, _wsgi):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('api_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('api_logging_level_c')
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

        #*** Set up REST API:
        wsgi = _wsgi
        self.data = {NMETA_INSTANCE: self, LOGGER: self.logger}
        mapper = wsgi.mapper
        #*** Register the RESTAPIController class:
        wsgi.register(RESTAPIController, {NMETA_INSTANCE : _nmeta,
                                                    LOGGER : self.logger})
        requirements = {}

        #*** Link to function for creating a DPAE:
        mapper.connect('dpae', self.url_dpae_base,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_create',
                       conditions=dict(method=['POST']))

        #*** Link to function for reading all DPAE:
        mapper.connect('dpae', self.url_dpae_base,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_read',
                       conditions=dict(method=['GET']))

        #*** Link to function for reading a particular DPAE:
        mapper.connect('dpae_uuid', self.url_dpae_uuid,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_read_uuid',
                       conditions=dict(method=['GET']))

        #*** Link to function for deleting a particular DPAE:
        mapper.connect('dpae', self.url_dpae_base,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_delete',
                       conditions=dict(method=['DELETE']))

        #*** Link to function for requesting send of sniff conf pkt to a DPAE:
        mapper.connect('dpae', self.url_dpae_uuid_sendconfpkt,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_send_sniff_conf_pkt',
                       conditions=dict(method=['POST']))

        #*** Link to function for setting DPAE interface TC state:
        mapper.connect('dpae', self.url_dpae_uuid_tc_state,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_tc_state_update',
                       conditions=dict(method=['PUT']))

        #*** Link to function for setting DPAE interface TC state:
        mapper.connect('dpae', self.url_dpae_uuid_keepalive,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_keepalive',
                       conditions=dict(method=['PUT']))

        #*** Link to function for getting main policy:
        mapper.connect('dpae', self.url_dpae_uuid_main_policy,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_main_policy_read',
                       conditions=dict(method=['GET']))

        #*** Link to function for getting optimised TC rules:
        mapper.connect('dpae', self.url_dpae_uuid_tc_opt_rules,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_tc_opt_rules_read',
                       conditions=dict(method=['GET']))

        #*** Link to function for posting a DPAE interface TC classification:
        mapper.connect('dpae', self.url_dpae_uuid_tc_classify,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_dpae_tc_classify_advice',
                       conditions=dict(method=['POST']))

        #*** Link to function for reading the IDMAC table:
        mapper.connect('general', self.url_idmac,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='rest_idmac_read',
                       conditions=dict(method=['GET']))

