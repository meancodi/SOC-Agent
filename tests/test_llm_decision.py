import json

from agent.llm import LocalLLM


llm = LocalLLM()


messages = [
    {
        "role": "system",
        "content": """
You are a SOC investigation agent.

You must decide what action to take.

Available tools:
- get_alert(alert_id)
- get_authentication_events(agent_id, start_time, end_time)
- get_process_events(agent_id, start_time, end_time)

Return only the requested structured decision.
"""
    },
    {
        "role": "user",
        "content": """
We are investigating alert:

WJuiCqAB0yAL2NcCZXbq

The alert has not yet been retrieved.

What should you do next?
"""
    }
]


result = llm.decide(messages)

print("Raw response:")
print(result)

print()

decision = json.loads(result)

print("Parsed decision:")
print(decision)