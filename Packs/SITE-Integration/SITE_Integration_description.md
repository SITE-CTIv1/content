## SITE Feed Integration
The SITE Feed Integration enables automatic ingestion of Indicators of Compromise (IOCs) from the SITE Intelligence database into XSOAR. This integration supports ingestion of the following system objects:

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

## Configure Integration 
Enter the following required settings:
   - Platform Base URL: 'https://intel.site.sa'
   - API ID: The unique identifier for API access. 
   - API Token: Token used for authenticating with the platform.
   - Polling Interval: Set the time interval (in minutes) for fetching IOCs.
   - Severity Level: Specify severity for filtering indicators.
