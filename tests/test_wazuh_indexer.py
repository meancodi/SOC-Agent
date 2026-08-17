from wazuh_indexer import WazuhIndexerClient

client = WazuhIndexerClient()

query = {
    "bool": {
        "must": [
            {
                "term": {
                    "agent.id": "001"
                }
            },
            {
                "term": {
                    "rule.id": "2502"
                }
            }
        ]
    }
}

result = client.search(
    index="wazuh-alerts-4.x-2026.08.16",
    query=query,
    size=5
)

hits = result["hits"]["hits"]

print(f"Found {len(hits)} matching alerts")

for hit in hits:
    source = hit["_source"]

    print()
    print()
    print("Alert ID:", hit["_id"])
    print("Agent:", source["agent"]["name"])
    print("Rule:", source["rule"]["id"])
    print("Level:", source["rule"]["level"])
    print("Description:", source["rule"]["description"])
    print("Log:", source["full_log"])