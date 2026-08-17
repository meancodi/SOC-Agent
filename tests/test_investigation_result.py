from state.investigation import InvestigationState
from agent.investigator import Investigator
from pretty_json import format_json


ALERT_ID = "WJuiCqAB0yAL2NcCZXbq"


state = InvestigationState(
    incident_id=ALERT_ID
)

investigator = Investigator(
    state=state,
    max_steps=10
)

result = investigator.run()

print()
print("=" * 60)
print("FINAL RESULT")
print("=" * 60)

if result is None:
    raise RuntimeError(
        "Investigator finished without producing a result."
    )

print(
    result.to_dict()
)

print()
print("State final_report:")

print(format_json(state.final_report))