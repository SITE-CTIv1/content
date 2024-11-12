## SITE Feed Integration

## Overview
Saudi Information Technology Company (SITE) empowers organizations with secure-by-design solutions that drive innovation and foster growth. Leveraging robust capabilities and strategic international partnerships, SITE delivers tailored services across cybersecurity, cloud computing, and systems integration, supporting businesses in today’s fast-evolving digital landscape. The SITE Feed Integration Integration for Palo Alto Cortex XSOAR enables automated ingestion of Indicators of Compromise (IOCs) directly from SITE Intelligence database into the Cortex XSOAR system. This integration allows security teams to streamline threat intelligence management by automatically fetching and categorizing IOCs. With capabilities to filter by severity, type, and last seen time, this integration is suitable for monitoring a variety of threat indicators.
This integration supports ingestion of the following system objects:
- Indicators
  - SHA-1
  - SHA-256
  - MD5
  - IP Address
  - Fully Qualified Domain Name (FQDN)

- Relations
  - Malware
  - Threat Actor
  - Attack Pattern

## Key Features
- Automatic IOC Ingestion: Fetch IOCs from a designated platform at regular intervals.
- Filter Options: Retrieve indicators based on severity, type, and timeframe.
- Related Indicators: Establish relationships between indicators for deeper insights.
- Tags and Context: Add customizable tags and Traffic Light Protocol (TLP) designations to each indicator for easy categorization and filtering.

## Prerequisites
- Access to your platform with API credentials (API ID and Token).
- An active Palo Alto Cortex XSOAR environment.

## Configuration
To configure the IOC Ingestion Integration:
1. Go to Settings > Integrations > Servers & Services.
2. Locate IOC Ingestor and click Add instance to create and configure a new integration instance.
3. Enter the following required settings:
   - Platform Base URL: Base URL of your threat intelligence platform.
   - API ID: The unique identifier for API access.
   - API Token: Token used for authenticating with the platform.
   - Polling Interval: Set the time interval (in minutes) for fetching IOCs.
   - Severity Level: Specify severity for filtering indicators.
4. Test the integration instance to verify the connection.

## Commands
This integration provides the following commands, which can be executed in Cortex XSOAR:

 1. `test-module`
- Description: Tests the connectivity to the platform.
- Usage: `!test-module`
- Output: `ok` if the connection is successful.

 2. `site-get-indicators`
- Description: Retrieves indicators from the platform.
- Arguments:
  - `limit` (optional): The maximum number of indicators to fetch.
- Usage: `!site-get-indicators limit=10`

 3. `fetch-indicators`
- Description: Ingests indicators directly into Cortex XSOAR.
- Usage: This command is automatically invoked as part of the scheduled fetch.

## Example Usage
Below are example commands to interact with this integration:

```bash
!test-module
!site-get-indicators limit=10
```

## Running Tests
To ensure that your integration is functioning as expected, run the following test cases:
1. Connectivity Test: Use `test-module` to confirm that the integration is connected and authenticated.
2. Fetch Indicator Test: Use `site-get-indicators` with a limit argument to fetch a sample of IOCs.

## Command Examples
To create command examples for generating documentation:
1. Create a `command_examples` file in the integration’s directory.
2. Add commands like `!test-module` and `!site-get-indicators limit=10`, one per line.

## Generating Documentation
To auto-generate documentation:
1. Set up your environment variables: `DEMISTO_BASE_URL` and `DEMISTO_API_KEY`.
2. Run the `demisto-sdk generate-docs` command with your YAML file as input, along with the `command_examples` file.
3. Ensure the `command_examples` file is checked in to your git repository for future reference.

