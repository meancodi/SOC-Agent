
from wazuh_indexer import WazuhIndexerClient
from pretty_json import format_json

client = WazuhIndexerClient()

alert_id = "V5uiCqAB0yAL2NcCYXbz"

result = client.get_alert(alert_id=alert_id)

if result is None:
    print("No result found")
else:
    print(format_json(result))