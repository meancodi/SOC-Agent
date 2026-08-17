
from wazuh_client import WazuhClient
from pretty_json import format_json

client = WazuhClient()

client.authenticate()


print("Authentication successful")

result = client.get("/agents")

print(format_json(result, style="github-dark"))