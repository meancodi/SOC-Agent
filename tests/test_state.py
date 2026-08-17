from state.investigation import InvestigationState


state = InvestigationState(
    "WJuiCqAB0yAL2NcCZXbq"
)

print("Initial status:", state.status)

state.set_alert({
    "id": "WJuiCqAB0yAL2NcCZXbq",
    "rule": {
        "id": "2502",
        "level": 10
    }
})

state.add_evidence({
    "type": "authentication",
    "count": 8
})

state.add_tool_call(
    "get_authentication_events",
    {
        "agent_id": "001"
    },
    {
        "count": 8
    }
)

state.add_finding(
    "Multiple authentication failures were observed."
)

state.set_status("investigating")

print()
print("Incident:", state.incident_id)
print("Alert:", state.alert)
print("Evidence:", state.evidence)
print("Tool calls:", state.tool_calls)
print("Findings:", state.findings)
print("Status:", state.status)