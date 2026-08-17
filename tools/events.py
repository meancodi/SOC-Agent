from wazuh_indexer import WazuhIndexerClient


def search_wazuh_events(
    agent_id: str,
    start_time: str,
    end_time: str
):
    """
    Search all Wazuh events for an agent within a time range.

    This intentionally performs a broad search. The investigator
    is responsible for interpreting and correlating the returned
    events.
    """

    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValueError(
            "agent_id must be a non-empty string"
        )

    if not isinstance(start_time, str) or not start_time.strip():
        raise ValueError(
            "start_time must be a non-empty string"
        )

    if not isinstance(end_time, str) or not end_time.strip():
        raise ValueError(
            "end_time must be a non-empty string"
        )

    client = WazuhIndexerClient()

    result = client.search_events(
        agent_id=agent_id.strip(),
        start_time=start_time.strip(),
        end_time=end_time.strip()
    )

    hits = result.get("hits", {}).get("hits", [])

    events = []

    for hit in hits:
        source = hit.get("_source", {})

        events.append({
            "event_id": hit.get("_id"),
            "timestamp": source.get("timestamp"),
            "agent": source.get("agent"),
            "rule": source.get("rule"),
            "decoder": source.get("decoder"),
            "data": source.get("data"),
            "full_log": source.get("full_log")
        })

    return {
        "status": "success",
        "count": len(events),
        "events": events
    }