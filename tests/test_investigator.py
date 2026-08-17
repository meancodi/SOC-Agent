from agent.investigator import Investigator
from state.investigation import InvestigationState


ALERT_ID = "WJuiCqAB0yAL2NcCZXbq"


state = InvestigationState(ALERT_ID)

investigator = Investigator(state)

investigator.run(max_steps=10)


print()
print("Investigation complete.")
print("Status:", state.status)
print("Tool calls:", len(state.tool_calls))
print("Evidence items:", len(state.evidence))