

from tools.authentication import get_authentication_events


result = get_authentication_events(
    agent_id="001",
    start_time="2026-08-16T12:48:28Z",
    end_time="2026-08-16T12:58:28Z"
)

print(f"Found {result['count']} authentication events")

for event in result["events"]:
    print()
    print("ID:", event["event_id"])
    print("Timestamp:", event["timestamp"])
    print("Decoder:", event["decoder"])
    print("Rule:", event["rule"])
    print("Data:", event["data"])
    print("Log:", event["full_log"])