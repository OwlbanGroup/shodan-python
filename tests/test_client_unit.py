"""Offline unit tests for the shodan client and stream modules.

These tests don't require an API key or network access - all of the HTTP
interactions are mocked out. Run them with:

    python -m unittest tests.test_client_unit -v
"""
import unittest
from unittest.mock import MagicMock, Mock, patch

import requests

import shodan
from shodan.exception import APIError
from shodan.stream import Stream


def make_response(status_code=200, json_data=None, text='', headers=None):
    """Create a fake requests.Response object."""
    resp = Mock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError('No JSON could be decoded')
    resp.text = text
    resp.headers = headers or {}
    return resp


class ShodanClientUnitTest(unittest.TestCase):
    """Test the Shodan REST API wrapper without any network access."""

    def setUp(self):
        # Disable the built-in rate limiter and stub out sleep() so the tests stay fast
        self.api = shodan.Shodan('TESTKEY')
        self.api.api_rate_limit = 0
        self.mock_sleep = MagicMock()
        patcher = patch('shodan.client.time.sleep', self.mock_sleep)
        patcher.start()
        self.addCleanup(patcher.stop)

        # Replace the real HTTP session with a mock
        self.session = MagicMock()
        self.api._session = self.session

    def test_request_success(self):
        self.session.get.return_value = make_response(json_data={'plan': 'unittest'})
        self.assertEqual(self.api.info(), {'plan': 'unittest'})
        self.assertIn('/api-info', self.session.get.call_args[0][0])
        self.assertEqual(self.session.get.call_args[1]['params']['key'], 'TESTKEY')

    def test_timeout_is_passed_to_requests(self):
        self.api.timeout = 30
        self.session.get.return_value = make_response(json_data={'ok': True})
        self.api.info()
        self.assertEqual(self.session.get.call_args[1]['timeout'], 30)

    def test_retries_on_server_errors(self):
        self.session.get.side_effect = [
            make_response(status_code=502),
            make_response(status_code=503),
            make_response(json_data={'ok': True}),
        ]
        self.assertEqual(self.api.info(), {'ok': True})
        self.assertEqual(self.session.get.call_count, 3)
        self.mock_sleep.assert_any_call(1)
        self.mock_sleep.assert_any_call(2)

    def test_server_error_exhausts_retries(self):
        self.session.get.return_value = make_response(status_code=502)
        with self.assertRaises(APIError) as ctx:
            self.api.info()
        self.assertIn('Bad Gateway', str(ctx.exception))
        self.assertEqual(self.session.get.call_count, 4)  # 1 initial attempt + 3 retries

    def test_retries_on_connection_errors(self):
        self.session.get.side_effect = [
            requests.ConnectionError,
            requests.ConnectionError,
            make_response(json_data={'ok': True}),
        ]
        self.assertEqual(self.api.info(), {'ok': True})
        self.assertEqual(self.session.get.call_count, 3)

    def test_connection_error_exhausts_retries(self):
        self.session.get.side_effect = requests.ConnectionError
        with self.assertRaises(APIError) as ctx:
            self.api.info()
        self.assertIn('Unable to connect', str(ctx.exception))
        self.assertEqual(self.session.get.call_count, 4)

    def test_rate_limit_honors_retry_after(self):
        self.session.get.side_effect = [
            make_response(status_code=429, headers={'Retry-After': '7'}),
            make_response(json_data={'ok': True}),
        ]
        self.assertEqual(self.api.info(), {'ok': True})
        self.mock_sleep.assert_any_call(7)
        self.assertEqual(self.session.get.call_count, 2)

    def test_rate_limit_exhausts_retries(self):
        self.session.get.return_value = make_response(status_code=429)
        with self.assertRaises(APIError) as ctx:
            self.api.info()
        self.assertIn('Rate limit', str(ctx.exception))

    def test_error_message_extracted_from_unexpected_status_code(self):
        self.session.get.return_value = make_response(status_code=404, json_data={'error': 'not found'})
        with self.assertRaises(APIError) as ctx:
            self.api.info()
        self.assertEqual(str(ctx.exception), 'not found')

    def test_html_401_raises_invalid_api_key(self):
        self.session.get.return_value = make_response(status_code=401, text='<html>401</html>')
        with self.assertRaises(APIError) as ctx:
            self.api.info()
        self.assertEqual(str(ctx.exception), 'Invalid API key')

    def test_invalid_json_raises_api_error(self):
        self.session.get.return_value = make_response(status_code=200)
        with self.assertRaises(APIError) as ctx:
            self.api.info()
        self.assertIn('Unable to parse JSON', str(ctx.exception))

    def test_error_field_in_json_raises(self):
        self.session.get.return_value = make_response(json_data={'error': 'query is empty'})
        with self.assertRaises(APIError) as ctx:
            self.api.info()
        self.assertEqual(str(ctx.exception), 'query is empty')

    def test_account_profile(self):
        self.session.get.return_value = make_response(json_data={'display_name': 'tester'})
        self.assertEqual(self.api.account_profile(), {'display_name': 'tester'})
        self.assertIn('/account/profile', self.session.get.call_args[0][0])

    def test_dns_reverse_lookup(self):
        self.session.get.return_value = make_response(json_data={'1.1.1.1': ['one.one.one.one']})
        result = self.api.dns.reverse_lookup(['1.1.1.1', '8.8.8.8'])
        self.assertEqual(result, {'1.1.1.1': ['one.one.one.one']})
        self.assertIn('/dns/reverse', self.session.get.call_args[0][0])
        self.assertEqual(self.session.get.call_args[1]['params']['ips'], '1.1.1.1,8.8.8.8')

    def test_dns_reverse_lookup_single_ip(self):
        self.session.get.return_value = make_response(json_data={})
        self.api.dns.reverse_lookup('1.1.1.1')
        self.assertEqual(self.session.get.call_args[1]['params']['ips'], '1.1.1.1')


class StreamUnitTest(unittest.TestCase):
    """Test the streaming API wrapper without any network access."""

    def setUp(self):
        self.mock_sleep = MagicMock()
        patcher = patch('shodan.stream.time.sleep', self.mock_sleep)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_524_without_timeout_retries_instead_of_crashing(self):
        stream = Stream('TESTKEY')
        resp_524 = Mock(status_code=524)
        resp_200 = Mock(status_code=200, encoding='utf-8')
        with patch('shodan.stream.requests.get', side_effect=[resp_524, resp_200]) as mock_get:
            req = stream._create_stream('/shodan/banners', timeout=None)
        self.assertIs(req, resp_200)
        self.assertEqual(mock_get.call_count, 2)
        self.mock_sleep.assert_any_call(1)

    def test_invalid_api_key_raises_api_error(self):
        stream = Stream('TESTKEY')
        resp = Mock(status_code=401, text='{"error": "bad key"}')
        with patch('shodan.stream.requests.get', return_value=resp):
            with self.assertRaises(APIError) as ctx:
                stream._create_stream('/shodan/banners')
        self.assertEqual(str(ctx.exception), 'bad key')

    def test_connection_failure_raises_api_error(self):
        stream = Stream('TESTKEY')
        with patch('shodan.stream.requests.get', side_effect=requests.ConnectionError):
            with self.assertRaises(APIError) as ctx:
                stream._create_stream('/shodan/banners')
        self.assertIn('Unable to contact', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
