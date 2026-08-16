import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wazuh_indexer import WazuhIndexerClient


def get_authentication_events(agent_id: str, start_time: str, end_time: str):
    """
    Retrieve authentication-related events for an endpoint
    within a specified time window
    """

    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValueError("agent_id must be a non-empty string")

    if not isinstance(start_time, str) or not start_time.strip():
        raise ValueError("start_time must be a non-empty string")

    if not isinstance(end_time, str) or not end_time.strip():
        raise ValueError("end_time must be a non-empty string")

    client = WazuhIndexerClient()

    result = client.search_authentication_events(
        agent_id=agent_id.strip(),
        start_time=start_time.strip(),
        end_time=end_time.strip()
    )

    hits = result["hits"]["hits"]

    events = []

    for hit in hits:
        source = hit["_source"]

        events.append({
            "event_id": hit["_id"],
            "timestamp": source.get("timestamp"),
            "agent": source.get("agent"),
            "data": source.get("data"),
            "rule": source.get("rule"),
            "decoder": source.get("decoder"),
            "full_log": source.get("full_log")
        })

    return {
        "status": "success",
        "count": len(events),
        "events": events
    }