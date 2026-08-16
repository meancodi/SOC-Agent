import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wazuh_indexer import WazuhIndexerClient


client = WazuhIndexerClient()

result = client.search_events(
    agent_id="001",
    start_time="2026-08-16T12:48:28Z",
    end_time="2026-08-16T12:58:28Z"
)

print(type(result))
print(result["hits"]["total"])

for hit in result["hits"]["hits"]:
    print(hit["_id"])