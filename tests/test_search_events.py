import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../tools/")))

from events import search_wazuh_events


result = search_wazuh_events(
    agent_id="001",
    start_time="2026-08-16T12:48:28Z",
    end_time="2026-08-16T12:58:28Z"
)

print(f"Found {result['count']} events")

for event in result["events"]:
    print()
    print("ID:", event["event_id"])
    print("Timestamp:", event["timestamp"])
    print("Rule:", event["rule"])
    print("Log:", event["full_log"])