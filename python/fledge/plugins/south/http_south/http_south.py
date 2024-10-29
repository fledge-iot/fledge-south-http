# -*- coding: utf-8 -*-

# FLEDGE_BEGIN
# See: http://fledge-iot.readthedocs.io/
# FLEDGE_END

"""HTTP Listener handler for sensor readings"""
import asyncio
import copy
import json
from datetime import datetime, timezone
import os
import ssl
import logging
import base64

from threading import Thread
from aiohttp import web

import numpy as np

from fledge.common import logger
from fledge.common.web import middleware
import async_ingest

__author__ = "Amarendra K Sinha"
__copyright__ = "Copyright (c) 2017 Dianomic Systems"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_LOGGER = logger.setup(__name__, level=logging.INFO)
c_callback = None
c_ingest_ref = None
loop = None
t = None
_FLEDGE_DATA = os.getenv("FLEDGE_DATA", default=None)
_FLEDGE_ROOT = os.getenv("FLEDGE_ROOT", default='/usr/local/fledge')

_CONFIG_CATEGORY_NAME = 'HTTP_SOUTH'
_CONFIG_CATEGORY_DESCRIPTION = 'South Plugin HTTP Listener'
_DEFAULT_CONFIG = {
    'plugin': {
        'description': 'HTTP Listener South Plugin',
        'type': 'string',
        'default': 'http_south',
        'readonly': 'true'
    },
    'host': {
        'description': 'Address to accept data on',
        'type': 'string',
        'default': '0.0.0.0',
        'order': '1',
        'displayName': 'Host'
    },
    'port': {
        'description': 'Port to listen on',
        'type': 'integer',
        'default': '6683',
        'order': '2',
        'displayName': 'Port'
    },
    'uri': {
        'description': 'URI to accept data on',
        'type': 'string',
        'default': 'sensor-reading',
        'order': '3',
        'displayName': 'URI'
    },
    'assetNamePrefix': {
        'description': 'Asset name prefix',
        'type': 'string',
        'default': 'http-',
        'order': '4',
        'displayName': 'Asset Name Prefix'
    },
    'enableHttp': {
        'description': 'Enable HTTP (Set false to use HTTPS)',
        'type': 'boolean',
        'default': 'true',
        'order': '5',
        'displayName': 'Enable HTTP'
    },
    'httpsPort': {
        'description': 'Port to accept HTTPS connections on',
        'type': 'integer',
        'default': '6684',
        'order': '6',
        'displayName': 'HTTPS Port'
    },
    'certificateName': {
        'description': 'Certificate file name',
        'type': 'string',
        'default': 'fledge',
        'order': '7',
        'displayName': 'Certificate Name'
    },
    'enableCORS': {
        'description': 'Enable Cross Origin Resource Sharing',
        'type': 'boolean',
        'default': 'false',
        'order': '8',
        'displayName': 'Enable CORS'
    },
    'headers': {
        'description': 'CORS configuration Access-Control-* response headers expressed in JSON document. '
                       'For example: {"Access-Control-Origin": "http://example.com", '
                       '"Access-Control-Allow-Headers": "*"}. ',
        'type': 'JSON',
        'default': '{}',
        'order': '9',
        'displayName': 'Response Headers',
        "validity": "enableCORS == \"true\""
    }
}


def plugin_info():
    return {
        'name': 'HTTP South Listener',
        'version': '2.6.0',
        'mode': 'async',
        'type': 'south',
        'interface': '1.0',
        'config': _DEFAULT_CONFIG
    }


def plugin_init(config):
    """Registers HTTP Listener handler to accept sensor readings

    Args:
        config: JSON configuration document for the South plugin configuration category
    Returns:
        handle: JSON object to be used in future calls to the plugin
    Raises:
    """
    handle = copy.deepcopy(config)
    return handle


def plugin_start(data):
    def enable_cors(_app, _conf):
        """ implements Cross Origin Resource Sharing (CORS) support """
        import aiohttp_cors

        # Default Resource options
        allowed_origin = "*"
        allowed_methods = ["POST", "OPTIONS"]
        allowed_credentials = True
        exposed_headers = "*"
        allowed_headers = "*"
        max_age = None
        if _conf:
            # Overwrite resource options
            headers_prefix = "Access-Control"
            origin = "{}-Allow-Origin".format(headers_prefix)
            methods = "{}-Allow-Methods".format(headers_prefix)
            credentials = "{}-Allow-Credentials".format(headers_prefix)
            exp_headers = "{}-Expose-Headers".format(headers_prefix)
            al_headers = "{}-Allow-Headers".format(headers_prefix)
            age = "{}-Max-Age".format(headers_prefix)
            if origin in _conf:
                allowed_origin = _conf[origin]
            if methods in _conf:
                allowed_methods = _conf[methods]
            if credentials in _conf:
                allowed_credentials = True if _conf[credentials] else False
            if exp_headers in _conf:
                exposed_headers = (_conf[exp_headers],)
            if al_headers in _conf:
                allowed_headers = (_conf[al_headers],)
            if age in _conf:
                max_age = int(_conf[age])

        # Configure CORS settings.
        cors = aiohttp_cors.setup(_app, defaults={
            allowed_origin: aiohttp_cors.ResourceOptions(
                allow_methods=allowed_methods,
                allow_credentials=allowed_credentials,
                expose_headers=exposed_headers,
                allow_headers=allowed_headers,
                max_age=max_age
            )})

        # Configure CORS on routes.
        for route in list(_app.router.routes()):
            cors.add(route)

    global loop, t
    _LOGGER.info("plugin_start called")

    loop = asyncio.new_event_loop()
    try:
        host = data['host']['value']
        port = data['port']['value']
        uri = data['uri']['value']

        http_south_ingest = HttpSouthIngest(config=data)
        app = web.Application(middlewares=[middleware.error_middleware], loop=loop, client_max_size=1024**3)
        app.router.add_route('POST', '/{}'.format(uri), http_south_ingest.render_post)
        if data['enableCORS']['value'] == 'true':
            cors_header = data['headers']['value']
            cors_options = cors_header if isinstance(cors_header, dict) else json.loads(cors_header)
            enable_cors(app, cors_options)
        handler = app.make_handler(loop=loop)

        # SSL context
        ssl_ctx = None

        is_https = True if data['enableHttp']['value'] == 'false' else False
        if is_https:
            port = data['httpsPort']['value']
            cert_name = data['certificateName']['value']
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            cert, key = get_certificate(cert_name)
            _LOGGER.info('Loading TLS certificate %s and key %s', cert, key)
            ssl_ctx.load_cert_chain(cert, key)

        server_coro = loop.create_server(handler, host, port, ssl=ssl_ctx)
        future = asyncio.ensure_future(server_coro, loop=loop)

        data['app'] = app
        data['handler'] = handler
        data['server'] = None

        def f_callback(f):
            # _LOGGER.info(repr(f.result()))
            """ <Server sockets=
            [<socket.socket fd=17, family=AddressFamily.AF_INET, type=2049,proto=6, laddr=('0.0.0.0', 6683)>]>"""
            data['server'] = f.result()

        future.add_done_callback(f_callback)

        def run():
            global loop
            loop.run_forever()

        t = Thread(target=run)
        t.start()
    except Exception as e:
        _LOGGER.exception(str(e))


def plugin_reconfigure(handle, new_config):
    """ Reconfigures the plugin

    it should be called when the configuration of the plugin is changed during the operation of the South service;
    The new configuration category should be passed.

    Args:
        handle: handle returned by the plugin initialisation call
        new_config: JSON object representing the new configuration category for the category
    Returns:
        new_handle: new handle to be used in the future calls
    Raises:
    """
    global loop
    _LOGGER.info("Old config for HTTP south plugin {} \n new config {}".format(handle, new_config))

    # plugin_shutdown
    plugin_shutdown(handle)

    # plugin_init
    new_handle = plugin_init(new_config)

    # plugin_start
    plugin_start(new_handle)

    return new_handle


def plugin_shutdown(handle):
    """ Shutdowns the plugin doing required cleanup, to be called prior to the South service being shut down.

    Args:
        handle: handle returned by the plugin initialisation call
    Returns:
    Raises:
    """
    global loop, t
    try:
        app = handle['app']
        handler = handle['handler']
        server = handle['server']
        if server:
            server.close()
            asyncio.ensure_future(server.wait_closed(), loop=loop)
            asyncio.ensure_future(app.shutdown(), loop=loop)
            asyncio.ensure_future(handler.shutdown(60.0), loop=loop)
            asyncio.ensure_future(app.cleanup(), loop=loop)
            try:
                pending = asyncio.all_tasks()
            except AttributeError:
                # For compatibility with python versions 3.6 or earlier.
                # asyncio.Task.all_tasks() is fully moved to asyncio.all_tasks() starting with 3.9; also applies to current_task.
                pending = asyncio.Task.all_tasks()
            if len(pending):
                loop.run_until_complete(asyncio.gather(*pending))
    except (RuntimeError, asyncio.CancelledError):
        pass
    except Exception as e:
        _LOGGER.exception(str(e))
    finally:
        loop = None
        t = None
    _LOGGER.info('South HTTP plugin shut down.')


def plugin_register_ingest(handle, callback, ingest_ref):
    """Required plugin interface component to communicate to South C server

    Args:
        handle: handle returned by the plugin initialisation call
        callback: C opaque object required to passed back to C->ingest method
        ingest_ref: C opaque object required to passed back to C->ingest method
    """
    global c_callback, c_ingest_ref
    c_callback = callback
    c_ingest_ref = ingest_ref


def get_certificate(cert_name):
    if _FLEDGE_DATA:
        certs_dir = os.path.expanduser(_FLEDGE_DATA + '/etc/certs')
    else:
        certs_dir = os.path.expanduser(_FLEDGE_ROOT + '/data/etc/certs')

    cert = certs_dir + '/{}.cert'.format(cert_name)
    key = certs_dir + '/{}.key'.format(cert_name)

    if not os.path.isfile(cert) or not os.path.isfile(key):
        _LOGGER.warning("%s certificate files are missing. Hence using default certificate.", cert_name)
        cert = certs_dir + '/fledge.cert'
        key = certs_dir + '/fledge.key'
        if not os.path.isfile(cert) or not os.path.isfile(key):
            _LOGGER.error("Certificates are missing")
            raise RuntimeError

    return cert, key


def json_numpy_obj_hook(dct):
    """Decodes a previously encoded numpy ndarray with proper shape and dtype.

    :param dct: (dict) json encoded ndarray
    :return: (ndarray) if input was an encoded ndarray
    """
    if isinstance(dct, dict) and '__ndarray__' in dct:
        data = dct['__ndarray__']
        if isinstance(data, str):
            data = data.encode(encoding='UTF-8')
        data = base64.b64decode(data)
        return np.frombuffer(data, dct['dtype']).reshape(dct['shape'])

    return dct


class HttpSouthIngest(object):
    """Handles incoming sensor readings from HTTP Listener"""

    def __init__(self, config):
        self.config_data = config

    async def render_post(self, request):
        """Store sensor readings from http_south to Fledge

        Args:
            request:
                The payload block decodes to JSON similar to the following:

                .. code-block:: python

                    [ {
                        "timestamp": "2017-01-02T01:02:03.23232Z-05:00",
                        "asset": "pump1",
                        "readings": {"humidity": 0.0, "temperature": -40.0}
                      },
                      ...
                    ]
        Example:
            curl -X POST http://localhost:6683/sensor-reading -d '[{"timestamp": "2017-01-02T01:02:03.23232Z-05:00",
                "asset": "pump1", "readings": {"humidity": 0.0, "temperature": -40.0}}]'
        """
        message = {'result': 'success'}
        try:
            try:
                payload_block = await request.json()
            except Exception:
                raise ValueError('Payload block must be a valid json')

            if type(payload_block) is not list:
                raise ValueError('Payload block must be a valid list')

            for payload in payload_block:
                asset = "{}{}".format(self.config_data['assetNamePrefix']['value'], payload['asset'])
                dt_str = payload['timestamp']

                if dt_str.endswith("Z"):
                    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
                    utc_dt = datetime.strptime(dt_str, fmt)
                    # Convert to local time zone
                    dt_str = str(utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None))

                # readings or sensor_values are optional
                try:
                    readings = payload['readings']
                except KeyError:
                    readings = payload['sensor_values']  # sensor_values is deprecated

                # if optional then
                # TODO: confirm, do we want to check this?
                if not isinstance(readings, dict):
                    raise ValueError('readings must be a dictionary')

                for dp,dpv in readings.items():
                    if not isinstance(dpv, dict):
                        continue

                    if '__ndarray__' in dpv:
                        readings[dp] = json.loads(dpv, object_hook=json_numpy_obj_hook)

                data = {
                    'asset': asset,
                    'timestamp': dt_str,
                    'readings': readings
                }
                async_ingest.ingest_callback(c_callback, c_ingest_ref, data)
        except (KeyError, ValueError, TypeError) as e:
            _LOGGER.exception("%d: %s", web.HTTPBadRequest.status_code, str(e))
            raise web.HTTPBadRequest(reason=e)
        except Exception as ex:
            _LOGGER.exception("%d: %s", web.HTTPInternalServerError.status_code, str(ex))
            raise web.HTTPInternalServerError(reason=str(ex))

        return web.json_response(message)
