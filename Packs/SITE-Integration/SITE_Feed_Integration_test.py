import pytest
import requests
from datetime import datetime
from unittest.mock import patch, Mock
from your_integration_file import Client, fetch_indicators, get_indicators_command, test_module

BASE_URL = "https://api.example.com"

@pytest.fixture
def client():
    return Client(base_url=BASE_URL, verify=False)


def test_client_init():
    """Test Client initialization."""
    client = Client(BASE_URL, verify=False)
    assert client._base_url == BASE_URL
    assert client._verify is False


@patch('your_integration_file.requests.Session.get')
def test_build_iterator(mock_get, client):
    """Test the build_iterator function."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = json.dumps({
        "objects": [
            {"type": "indicator", "name": "malicious.com", "created": "2023-01-01T12:00:00.000Z"},
            {"type": "indicator", "name": "badfilehash", "created": "2023-01-02T12:00:00.000Z"},
        ]
    })
    mock_get.return_value = mock_response

    indicators = client.build_iterator("2023-01-01T00:00:00.000Z", "High", "ALL", "3m")
    assert len(indicators) == 2
    assert indicators[0]["type"] == "indicator"
    assert indicators[1]["type"] == "indicator"


def test_fix_json_response():
    """Test the fix_json_response function."""
    response_text = '{"id":1}    {"id":2}'
    client = Client(BASE_URL, verify=False)
    fixed_text = client.fix_json_response(response_text)
    assert fixed_text == '{"id":1}, {"id":2}'


@patch('your_integration_file.fetch_indicators')
def test_get_indicators_command(mock_fetch_indicators, client):
    """Test the get_indicators_command."""
    mock_fetch_indicators.return_value = [
        {"value": "malicious.com", "type": "Domain"},
        {"value": "badfilehash", "type": "File"}
    ]

    params = {"tlp_color": "AMBER", "feedTags": "tag1,tag2"}
    args = {"limit": "2"}

    command_results = get_indicators_command(client, params, args)
    output = command_results.readable_output

    assert "malicious.com" in output
    assert "badfilehash" in output


@patch('your_integration_file.fetch_indicators')
def test_fetch_indicators(mock_fetch_indicators, client):
    """Test the fetch_indicators function."""
    mock_fetch_indicators.return_value = [
        {"value": "malicious.com", "type": "Domain"},
        {"value": "badfilehash", "type": "File"}
    ]
    indicators = fetch_indicators(client, limit=2)
    assert len(indicators) == 2
    assert indicators[0]["type"] == "Domain"
    assert indicators[1]["type"] == "File"


@patch('your_integration_file.requests.Session.get')
def test_test_module(mock_get, client):
    """Test the test_module function to validate connectivity."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = json.dumps({"objects": []})
    mock_get.return_value = mock_response

    result = test_module(client)
    assert result == "ok"
