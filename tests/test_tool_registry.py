
from agent.tool_registry import TOOLS, execute_tool


print("Registered tools:")

for name in TOOLS:
    print(f"  - {name}")


result = execute_tool(
    "get_alert",
    {
        "alert_id": "V5uiCqAB0yAL2NcCYXbz"
    }
)

print()
print("Tool result:")
print(result)