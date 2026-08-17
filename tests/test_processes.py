
from tools.processes import get_process_events


result = get_process_events(
    agent_id="001",
    start_time="2026-08-16T12:48:28Z",
    end_time="2026-08-16T12:58:28Z"
)

print(f"Found {result['count']} process/command events")

for event in result["events"]:
    print()
    print("ID:", event["event_id"])
    print("Timestamp:", event["timestamp"])
    print("User:", event["user"])
    print("Command:", event["command"])
    print("Working directory:", event["working_directory"])
    print("Terminal:", event["terminal"])
    print("Rule:", event["rule"])
    print("Log:", event["full_log"])