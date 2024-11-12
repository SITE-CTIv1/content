from typing import Dict, List, Optional
import requests
import json
from datetime import datetime

class Client:
    """Client class to interact with the service API"""

    def __init__(self, base_url: str, verify: bool = True, proxy: Optional[Dict[str, str]] = None):
        self._base_url = base_url
        self._verify = verify
        self._session = requests.Session()
        self._session.verify = verify
        if proxy:
            self._session.proxies = proxy

    def build_iterator(self, last_created_time: str, severity: str, indicator_type: str, last_seen: str) -> List:
        """Retrieves all entries from the feed starting after the last created time."""
        result = []

        # Define query parameters for the API request
        params = {
            "export_format": "stixv2F",
            "severity": severity,
            "indicator_type": indicator_type,
            "last_seen": last_seen
        }

        # Send the GET request to the API with the query parameters
        response = self._session.get(self._base_url, params=params)
        if response.status_code != 200:
            raise ValueError(f'Error in API call to {self._base_url} - {response.status_code} - {response.text}')

        try:
            res_json = json.loads(response.text)
            objects = res_json.get('objects', [])

            for obj in objects:
                created_time = obj.get('created')
                if created_time and created_time > last_created_time:
                    result.append({
                        'type': obj.get('type'),
                        'rawJSON': obj
                    })

        except ValueError as err:
            raise ValueError(f'Could not parse returned data as indicator. \n\nError message: {err}')
        return result

    def fix_json_response(self, response_text: str) -> str:
        """Fixes missing commas between JSON objects in the response text."""
        return response_text.replace('}    {', '}, {')

    def detect_indicator_type(self, pattern: str) -> str:
        """Detect the type of indicator based on the pattern."""
        if any(keyword in pattern for keyword in ['SHA-256', 'MD5', 'SHA-1']):
            return 'File'
        if 'ipv4-addr' in pattern:
            return 'IP'
        if 'domain-name' in pattern:
            return 'Domain'
        return auto_detect_indicator_type(pattern)

    def extract_related_indicators(self, relationships: List[Dict], objects: List[Dict]) -> List[Dict]:
        """Extracts related indicators from an indicator object."""
        related_indicators = []
        object_dict = {obj['id']: obj for obj in objects}
        for relation in relationships:
            source_id = relation.get('source_ref')
            target_id = relation.get('target_ref')
            if source_id in object_dict and target_id in object_dict:
                related_indicators.append(
                    EntityRelationship(
                        name='related-to',
                        entity_a=object_dict[source_id].get('name', source_id),
                        entity_a_type=object_dict[source_id].get('type'),
                        entity_b=object_dict[target_id].get('name', target_id),
                        entity_b_type=object_dict[target_id].get('type'),
                        reverse_name='related-to'
                    ).to_indicator()
                )
        return related_indicators

    def extract_attributes(self, attributes: List[Dict]):
        """Extracts attributes from an indicator object."""
        return [f"{attr.get('name')}: {attr.get('value')}" for attr in attributes]


def test_module(client: Client):
    fetch_indicators(client, limit=1)
    return 'ok'


def fetch_indicators(client: Client, tlp_color: Optional[str] = None, feed_tags: List = [], limit: int = 300,
                     create_relationships: bool = False) -> List[Dict]:
    integration_context = get_integration_context()
    last_created_time = integration_context.get('last_created_time', '1970-01-01T00:00:00.000Z')
    severity = "High"  # Set severity level
    indicator_type = "ALL"  # Set indicator type to "ALL"
    last_seen = "3m"  # Set last seen period

    try:
        iterator = client.build_iterator(last_created_time, severity, indicator_type, last_seen)
        indicators = []
        relationships = []
        objects = []

        if limit > 0:
            iterator = iterator[:limit]

        for item in iterator:
            rawJSON = item.get('rawJSON')
            obj_type = rawJSON.get('type')

            if obj_type == 'relationship':
                relationships.append(rawJSON)
            else:
                objects.append(rawJSON)

        for obj in objects:
            obj_type = obj.get('type')
            created_time = obj.get('created')
            if obj_type == 'indicator':
                value_ = obj.get('name')
                pattern = obj.get('pattern')
                attributes = obj.get("x_attributes")
                indicator_type = client.detect_indicator_type(pattern)
                related_indicators = client.extract_related_indicators(relationships, objects)
                feed_tags = client.extract_attributes(attributes)
                indicator_obj = {
                    'value': value_,
                    'type': indicator_type,
                    'rawJSON': obj,
                    'relationships': related_indicators
                }

                if feed_tags:
                    indicator_obj['fields'] = {'tags': feed_tags}

                if tlp_color:
                    indicator_obj.setdefault('fields', {})['trafficlightprotocol'] = tlp_color

                indicators.append(indicator_obj)

            elif obj_type in ['malware', 'attack-pattern', 'threat-actor']:
                indicator_obj = {
                    'value': obj.get('name'),
                    'type': obj_type.title().replace('-', ' '),
                    'rawJSON': obj
                }
                indicators.append(indicator_obj)

            # Update the last created time if this object's created time is later
            if created_time and created_time > last_created_time:
                last_created_time = created_time

        # Update the integration context with the latest created time
        integration_context['last_created_time'] = last_created_time
        set_integration_context(integration_context)

    except Exception as e:
        return_error(f'Error:\n{str(e)}')
    return indicators


def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]
                           ) -> CommandResults:
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown('Indicators from YourFeed:', indicators,
                                     headers=['value', 'type'], headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = params.get('tlp_color')
    limit = int(params.get('limit') or "0")
    create_relationships = argToBoolean(params.get('create_relationships', True))
    indicators = fetch_indicators(client, tlp_color, feed_tags, create_relationships=create_relationships,limit=limit)
    return indicators


def main():
    params = demisto.params()
    base_url = params.get('url')
    api_id = params.get('api_id')
    api_token = params.get('api_token')
    base_url = base_url + "/api/v1/threat-intelligence/export/" + api_id + "/?token=" + api_token
    insecure = not params.get('insecure', True)
    proxy = params.get('proxy', False)
    proxy_dict = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy_dict,
        )

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'site-get-indicators':
            return_results(get_indicators_command(client, params, args))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params)
            demisto.createIndicators(indicators)
        elif command == 'site-fetch-indicators':
            indicators = fetch_indicators_command(client, params)
            return_results(None)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('builtins', '__builtin__', '__main__'):
    try:
        main()
    except Exception as exception:
        return_error(exception)