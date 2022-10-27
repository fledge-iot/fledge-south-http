# -*- coding: utf-8 -*-

# FLEDGE_BEGIN
# See: http://fledge-iot.readthedocs.io/
# FLEDGE_END

import copy
import json
from unittest import mock
from unittest.mock import call, patch
import pytest
import aiohttp.web_exceptions
from aiohttp.test_utils import make_mocked_request
from aiohttp.streams import StreamReader
from multidict import CIMultiDict
from python.fledge.plugins.south.http_south import http_south
from python.fledge.plugins.south.http_south.http_south import HttpSouthIngest, async_ingest, _DEFAULT_CONFIG as config

__author__ = "Amarendra K Sinha, Ashish Jabble"
__copyright__ = "Copyright (c) 2017-2022 Dianomic Systems Inc."
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_NEW_CONFIG = {
    'plugin': {
        'description': 'South Plugin HTTP Listener',
        'type': 'string',
        'default': 'http_south'
    },
    'port': {
        'description': 'Port to listen on',
        'type': 'integer',
        'default': '1234',
        'value': '4321'
    },
    'host': {
        'description': 'Address to accept data on',
        'type': 'string',
        'default': 'localhost',
        'value': '127.0.0.1'
    },
    'uri': {
        'description': 'URI to accept data on',
        'type': 'string',
        'default': 'sensor-reading',
        'value': 'sensor-reading'
    },
    'enableHttp': {
        'description': 'Enable HTTP (Set false to use HTTPS)',
        'type': 'boolean',
        'default': 'true',
        'value': 'true'
    },
    'enableCORS': {
        'description': 'Enable Cross Origin Resource Sharing',
        'type': 'boolean',
        'default': 'false',
        'value': 'false'
    }
}


def test_plugin_contract():
    # Evaluates if the plugin has all the required methods
    assert callable(getattr(http_south, 'plugin_info'))
    assert callable(getattr(http_south, 'plugin_init'))
    assert callable(getattr(http_south, 'plugin_start'))
    assert callable(getattr(http_south, 'plugin_shutdown'))
    assert callable(getattr(http_south, 'plugin_reconfigure'))


def test_plugin_info():
    assert http_south.plugin_info() == {
        'name': 'HTTP South Listener',
        'version': '2.0.1',
        'mode': 'async',
        'type': 'south',
        'interface': '1.0',
        'config': config
    }


def test_plugin_init():
    assert http_south.plugin_init(config) == config


def test_plugin_start():
    # GIVEN
    config_data = copy.deepcopy(config)
    config_data['port']['value'] = config_data['port']['default']
    config_data['host']['value'] = config_data['host']['default']
    config_data['uri']['value'] = config_data['uri']['default']
    config_data['enableHttp']['value'] = config_data['enableHttp']['default']
    config_data['enableCORS']['value'] = config_data['enableCORS']['default']

    # WHEN
    with patch.object(http_south._LOGGER, 'info') as patch_log_info:
        http_south.plugin_start(config_data)
        # THEN
        assert isinstance(config_data['app'], aiohttp.web.Application)
        assert isinstance(config_data['handler'], aiohttp.web_server.Server)
        # assert isinstance(config_data['server'], asyncio.base_events.Server)
        http_south.loop.stop()
        http_south.t._delete()
    assert 1 == patch_log_info.call_count
    patch_log_info.assert_called_with("plugin_start called")


def test_plugin_start_exception():
    config_data = copy.deepcopy(config)
    with patch.object(http_south._LOGGER, 'info') as patch_log_info:
        with patch.object(http_south._LOGGER, 'exception') as patch_log_exception:
            http_south.plugin_start(config_data)
        assert 1 == patch_log_exception.call_count
        patch_log_exception.assert_called_with("'value'")
    assert 1 == patch_log_info.call_count
    patch_log_info.assert_called_with("plugin_start called")


def test_plugin_reconfigure():
    # GIVEN
    config_data = copy.deepcopy(config)
    config_data['port']['value'] = config_data['port']['default']
    config_data['host']['value'] = config_data['host']['default']
    config_data['uri']['value'] = config_data['uri']['default']
    config_data['enableHttp']['value'] = config_data['enableHttp']['default']
    config_data['enableCORS']['value'] = config_data['enableCORS']['default']
    with patch.object(http_south, 'plugin_shutdown', return_value=True) as patch_shutdown:
        with patch.object(http_south, 'plugin_init', return_value=_NEW_CONFIG) as patch_init:
            with patch.object(http_south, 'plugin_start', return_value=True) as patch_start:
                with patch.object(http_south._LOGGER, 'info') as patch_log_info:
                    # WHEN
                    new_config = http_south.plugin_reconfigure(config_data, _NEW_CONFIG)
                    # THEN
                    assert _NEW_CONFIG == new_config
                assert 1 == patch_log_info.call_count
            assert 1 == patch_start.call_count
        assert 1 == patch_init.call_count
    assert 1 == patch_shutdown.call_count


def test_plugin_shutdown():
    # GIVEN
    config_data = copy.deepcopy(config)
    config_data['port']['value'] = config_data['port']['default']
    config_data['host']['value'] = config_data['host']['default']
    config_data['uri']['value'] = config_data['uri']['default']
    config_data['enableHttp']['value'] = config_data['enableHttp']['default']
    config_data['enableCORS']['value'] = config_data['enableCORS']['default']
    with patch.object(http_south._LOGGER, 'info') as patch_log_info:
        # WHEN
        http_south.plugin_start(config_data)
        # THEN
        http_south.plugin_shutdown(config_data)
    assert 2 == patch_log_info.call_count
    calls = [call('South HTTP plugin shut down.')]
    patch_log_info.assert_has_calls(calls, any_order=True)


@pytest.mark.skip(reason="server object is None in tests. To be investigated.")
def test_plugin_shutdown_error(mocker, unused_port, loop):
    # GIVEN
    port = {
        'description': 'Port to listen on',
        'type': 'integer',
        'default': str(unused_port()),
    }
    config_data = copy.deepcopy(config)
    mocker.patch.dict(config_data, {'port': port})
    config_data['port']['value'] = config_data['port']['default']
    config_data['host']['value'] = config_data['host']['default']
    config_data['uri']['value'] = config_data['uri']['default']
    config_data['enableHttp']['value'] = config_data['enableHttp']['default']
    log_exception = mocker.patch.object(http_south._LOGGER, "exception")
    log_info = mocker.patch.object(http_south._LOGGER, "info")

    # WHEN
    http_south.plugin_start(config_data)
    server = config_data['server']
    mocker.patch.object(server, 'wait_closed', side_effect=Exception)
    with pytest.raises(Exception):
        http_south.plugin_shutdown(config_data)

    # THEN
    assert 2 == log_info.call_count
    calls = [call('Stopping South HTTP plugin.')]
    log_info.assert_has_calls(calls, any_order=True)
    assert 1 == log_exception.call_count


class TestHttpSouthIngest(object):
    """ Unit tests fledge.plugins.south.http_south.http_south.HttpSouthIngest
    """
    def mock_request(self, data, loop):
        payload = StreamReader(loop=loop, limit=1, protocol=aiohttp.base_protocol.BaseProtocol(loop))
        payload.feed_data(data.encode())
        payload.feed_eof()

        protocol = mock.Mock()
        app = mock.Mock()
        headers = CIMultiDict([('CONTENT-TYPE', 'application/json')])
        req = make_mocked_request('POST', '/sensor-reading', headers=headers,
                                  protocol=protocol, payload=payload, app=app)

        return req

    async def test_render_post_reading_ok(self, loop):
        data = """[{
            "timestamp": "2017-01-02T01:02:03.23232Z-05:00",
            "asset": "sensor1",
            "key": "80a43623-ebe5-40d6-8d80-3f892da9b3b4",
            "readings": {
                "velocity": "500",
                "temperature": {
                    "value": "32",
                    "unit": "kelvin"
                }
            }
        }]"""

        with patch.object(async_ingest, 'ingest_callback') as patch_ingest_callback:
            request = self.mock_request(data, loop)
            config_data = copy.deepcopy(config)
            config_data['assetNamePrefix']['value'] = config_data['assetNamePrefix']['default']
            r = await HttpSouthIngest(config_data).render_post(request)
            retval = json.loads(r.body.decode())
            # Assert the POST request response
            assert 200 == r.status
            assert 'success' == retval['result']
        assert 1 == patch_ingest_callback.call_count

    async def test_render_post_sensor_values_ok(self, loop):
        data = """[{
            "timestamp": "2017-01-02T01:02:03.23232Z-05:00",
            "asset": "sensor1",
            "key": "80a43623-ebe5-40d6-8d80-3f892da9b3b4",
            "sensor_values": {
                "velocity": "500",
                "temperature": {
                    "value": "32",
                    "unit": "kelvin"
                }
            }
        }]"""
        with patch.object(async_ingest, 'ingest_callback') as patch_ingest_callback:
            request = self.mock_request(data, loop)
            config_data = copy.deepcopy(config)
            config_data['assetNamePrefix']['value'] = config_data['assetNamePrefix']['default']
            r = await HttpSouthIngest(config_data).render_post(request)
            retval = json.loads(r.body.decode())
            # Assert the POST request response
            assert 200 == r.status
            assert 'success' == retval['result']
        assert 1 == patch_ingest_callback.call_count

    async def test_render_post_invalid_payload(self, loop):
        data = "blah"
        msg = 'Payload block must be a valid json'
        with patch.object(async_ingest, 'ingest_callback') as patch_ingest_callback:
            with patch.object(http_south._LOGGER, 'exception') as patch_log_exc:
                with pytest.raises(aiohttp.web_exceptions.HTTPBadRequest) as ex:
                    request = self.mock_request(data, loop)
                    config_data = copy.deepcopy(config)
                    config_data['assetNamePrefix']['value'] = config_data['assetNamePrefix']['default']
                    r = await HttpSouthIngest(config_data).render_post(request)
                    assert 400 == r.status
                assert str(ex).endswith(msg)
            assert 1 == patch_log_exc.call_count
            patch_log_exc.assert_called_once_with('%d: %s', 400, msg)
        assert 0 == patch_ingest_callback.call_count

    async def test_render_post_reading_missing_delimiter(self, loop):
        data = """{
            "timestamp": "2017-01-02T01:02:03.23232Z-05:00",
            "asset": "sensor1",
            "key": "80a43623-ebe5-40d6-8d80-3f892da9b3b4",
            "readings": {
                "velocity": "500",
                "temperature": {
                    "value": "32",
                    "unit": "kelvin"
                }
        }"""
        msg = 'Payload block must be a valid json'
        with patch.object(async_ingest, 'ingest_callback') as patch_ingest_callback:
            with patch.object(http_south._LOGGER, 'exception') as patch_log_exc:
                with pytest.raises(aiohttp.web_exceptions.HTTPBadRequest) as ex:
                    request = self.mock_request(data, loop)
                    config_data = copy.deepcopy(config)
                    config_data['assetNamePrefix']['value'] = config_data['assetNamePrefix']['default']
                    r = await HttpSouthIngest(config_data).render_post(request)
                    assert 400 == r.status
                assert str(ex).endswith(msg)
            assert 1 == patch_log_exc.call_count
            patch_log_exc.assert_called_once_with('%d: %s', 400, msg)
        assert 0 == patch_ingest_callback.call_count

    async def test_render_post_reading_not_dict(self, loop):
        data = """[{
            "timestamp": "2017-01-02T01:02:03.23232Z-05:00",
            "asset": "sensor2",
            "key": "80a43623-ebe5-40d6-8d80-3f892da9b3b4",
            "readings": "500"
        }]"""
        msg = 'readings must be a dictionary'
        with patch.object(async_ingest, 'ingest_callback') as patch_ingest_callback:
            with patch.object(http_south._LOGGER, 'exception') as patch_log_exc:
                with pytest.raises(aiohttp.web_exceptions.HTTPBadRequest) as ex:
                    request = self.mock_request(data, loop)
                    config_data = copy.deepcopy(config)
                    config_data['assetNamePrefix']['value'] = config_data['assetNamePrefix']['default']
                    r = await HttpSouthIngest(config_data).render_post(request)
                    assert 400 == r.status
                assert str(ex).endswith(msg)
            assert 1 == patch_log_exc.call_count
            patch_log_exc.assert_called_once_with('%d: %s', 400, msg)
        assert 0 == patch_ingest_callback.call_count
