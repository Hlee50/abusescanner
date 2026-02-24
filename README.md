# Abuse.ch CLI
Abuse.ch CLI is a CLI API client, written in Python, that scans malicious URLs or file hashes through cross-querying multiple Abuse.ch databases.

This client queries the URLhaus, ThreatFox, and/or Malware Bazaar APIs to check URLs or file hashes against their respective databases. All published URLs, IOCs, and file hashes are known to be malicious.

An Auth-Key from your abuse.ch account (https://auth.abuse.ch/) is required for the client to make requests to any Abuse.ch API.

# Run the client
To run the client run the _abusechcli.py_ script.

### Reference API documentation
https://urlhaus-api.abuse.ch/

https://bazaar.abuse.ch/api/

https://threatfox.abuse.ch/api/
