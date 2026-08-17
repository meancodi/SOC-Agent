import json

from agent.llm import LocalLLM
from agent.tool_registry import (
    TOOLS,
    execute_tool,
    get_tool_descriptions
)
from state.investigation import InvestigationState


class Investigator:

    def __init__(
        self,
        state: InvestigationState,
        max_steps: int = 10,
        max_decision_retries: int = 2
    ):
        self.state = state
        self.llm = LocalLLM()

        self.max_steps = max_steps
        self.max_decision_retries = max_decision_retries

    # =========================================================
    # TOOL EXECUTION
    # =========================================================

    def execute(
        self,
        tool_name: str,
        arguments: dict
    ):
        """
        Execute an authorized tool and record its result.
        """

        result = execute_tool(
            tool_name,
            arguments
        )

        self.state.add_tool_call(
            tool_name,
            arguments,
            result
        )

        self.state.add_evidence(
            result
        )

        return result

    # =========================================================
    # INITIAL ALERT
    # =========================================================

    def retrieve_initial_alert(self):
        """
        Retrieve the initial Wazuh alert deterministically.

        The LLM does not decide whether this should happen.
        """

        if self.state.alert is not None:
            return self.state.alert

        alert_id = self.state.incident_id

        if not alert_id:
            raise ValueError(
                "Investigation requires an alert ID."
            )

        print()
        print("Retrieving initial alert...")
        print(f"Alert ID: {alert_id}")

        result = self.execute(
            "get_alert",
            {
                "alert_id": alert_id
            }
        )

        if result is None:
            raise ValueError(
                f"Alert not found: {alert_id}"
            )

        self.state.set_alert(
            result
        )

        return result

    # =========================================================
    # LLM CONTEXT
    # =========================================================

    def _build_investigation_context(self):
        """
        Build a compact representation of the investigation
        state for the LLM.

        Tool results are kept in evidence. Tool call history
        contains only metadata here to avoid duplicating large
        results in the model context.
        """

        tool_history = []

        for call in self.state.tool_calls:

            tool_history.append({
                "tool": call.get("tool"),
                "arguments": call.get("arguments")
            })

        return json.dumps(
            {
                "incident_id": self.state.incident_id,

                "alert": self.state.alert,

                "evidence": self.state.evidence,

                "tool_calls": tool_history,

                "findings": self.state.findings
            },
            indent=2,
            default=str
        )

    # =========================================================
    # SYSTEM PROMPT
    # =========================================================

    def _build_system_prompt(self):

        tool_descriptions = get_tool_descriptions()

        return f"""
You are a SOC investigation agent.

You are investigating one Wazuh security alert.

Your task is to collect enough evidence to understand the
incident and then decide when the investigation can finish.

AVAILABLE TOOLS

{json.dumps(tool_descriptions, indent=2)}

INVESTIGATION RULES

1. Only use tools listed above.

2. Never invent a tool.

3. Never invent an argument name.

4. Use exactly the parameter names defined for the selected tool.

5. Do not generate Wazuh DSL, OpenSearch queries, event_query
   objects, or arbitrary query structures.

6. search_wazuh_events returns broad event context for the
   specified agent and time range. Use it when broad context
   around the alert is useful.

7. get_authentication_events is available when authentication
   activity needs more focused investigation.

8. get_process_events is available when process or command
   execution activity needs more focused investigation.

9. The initial alert has already been retrieved. Do not call
   get_alert again.

10. Examine the alert and previously collected evidence before
    selecting another tool.

11. Do not finish immediately after retrieving the alert.

12. Collect additional evidence when the current evidence does
    not adequately explain the incident.

13. Do not repeat the exact same tool call unless there is a
    specific investigative reason.

14. Do not invent timestamps, agent IDs, or alert IDs. Reuse
    values present in the investigation state whenever possible.

15. Finish when the available evidence is sufficient to form
    a reasonable security assessment.

16. Return only the requested JSON decision.
"""

    # =========================================================
    # DECISION
    # =========================================================

    def decide_next_action(self):

        messages = [
            {
                "role": "system",
                "content": self._build_system_prompt()
            },
            {
                "role": "user",
                "content": self._build_investigation_context()
            }
        ]

        last_error = None

        for attempt in range(
            self.max_decision_retries + 1
        ):

            response = self.llm.decide(
                messages,
                allowed_tools=TOOLS.keys()
            )

            print()
            print("RAW LLM RESPONSE:")
            print(response)

            try:

                decision = json.loads(
                    response
                )

                self._validate_decision(
                    decision
                )

                return decision

            except (
                json.JSONDecodeError,
                ValueError
            ) as exc:

                last_error = str(exc)

                if attempt >= self.max_decision_retries:
                    break

                print()
                print(
                    "Invalid LLM decision."
                )
                print(
                    f"Reason: {last_error}"
                )
                print(
                    "Requesting a corrected decision..."
                )

                messages.append({
                    "role": "assistant",
                    "content": response
                })

                messages.append({
                    "role": "user",
                    "content": (
                        "Your previous decision was invalid.\n\n"
                        f"Validation error: {last_error}\n\n"
                        "Return a corrected JSON decision. "
                        "Use only the available tools and their "
                        "exact parameter names. Do not invent "
                        "arguments."
                    )
                })

        raise ValueError(
            "LLM failed to produce a valid investigation "
            f"decision after {self.max_decision_retries + 1} attempts. "
            f"Last error: {last_error}"
        )

    # =========================================================
    # DECISION VALIDATION
    # =========================================================

    def _validate_decision(
        self,
        decision
    ):

        if not isinstance(
            decision,
            dict
        ):
            raise ValueError(
                "LLM decision must be a JSON object."
            )

        action = decision.get(
            "action"
        )

        if action not in {
            "tool",
            "finish"
        }:
            raise ValueError(
                f"Invalid action: {action}"
            )

        # -----------------------------------------------------
        # FINISH
        # -----------------------------------------------------

        if action == "finish":

            if self.state.alert is None:
                raise ValueError(
                    "Cannot finish before retrieving "
                    "the initial alert."
                )

            investigative_calls = [
                call
                for call in self.state.tool_calls
                if call.get("tool") != "get_alert"
            ]

            if not investigative_calls:
                raise ValueError(
                    "Cannot finish immediately after retrieving "
                    "the alert. Collect additional evidence first."
                )

            return

        # -----------------------------------------------------
        # TOOL
        # -----------------------------------------------------

        tool_name = decision.get(
            "tool"
        )

        if tool_name not in TOOLS:
            raise ValueError(
                f"Unauthorized tool: {tool_name}"
            )

        if (
            tool_name == "get_alert"
            and self.state.alert is not None
        ):
            raise ValueError(
                "The initial alert has already been retrieved."
            )

        arguments = decision.get(
            "arguments"
        )

        if not isinstance(
            arguments,
            dict
        ):
            raise ValueError(
                "Tool arguments must be a JSON object."
            )

        tool_definition = TOOLS[
            tool_name
        ]

        parameters = tool_definition.get(
            "parameters",
            {}
        )

        required = tool_definition.get(
            "required",
            []
        )

        # -----------------------------------------------------
        # Unknown arguments
        # -----------------------------------------------------

        unknown_arguments = (
            set(arguments.keys())
            - set(parameters.keys())
        )

        if unknown_arguments:

            raise ValueError(
                f"Unknown arguments for {tool_name}: "
                f"{sorted(unknown_arguments)}"
            )

        # -----------------------------------------------------
        # Missing arguments
        # -----------------------------------------------------

        missing_arguments = [
            parameter
            for parameter in required
            if parameter not in arguments
        ]

        if missing_arguments:

            raise ValueError(
                f"Missing required arguments for "
                f"{tool_name}: "
                f"{missing_arguments}"
            )

        # -----------------------------------------------------
        # Basic type validation
        # -----------------------------------------------------

        for name, value in arguments.items():

            specification = parameters[name]

            expected_type = specification.get(
                "type"
            )

            if expected_type == "string":
                if not isinstance(
                    value,
                    str
                ):
                    raise ValueError(
                        f"Argument '{name}' for {tool_name} "
                        "must be a string."
                    )

        # -----------------------------------------------------
        # Duplicate tool call protection
        # -----------------------------------------------------

        for previous_call in self.state.tool_calls:

            if previous_call.get("tool") != tool_name:
                continue

            previous_arguments = (
                previous_call.get("arguments")
            )

            if previous_arguments == arguments:

                raise ValueError(
                    f"Tool {tool_name} has already been "
                    "called with the same arguments."
                )

    # =========================================================
    # MAIN LOOP
    # =========================================================

    def run(
        self,
        max_steps=None
    ):

        if max_steps is None:
            max_steps = self.max_steps

        self.state.set_status(
            "investigating"
        )

        print(
            "Starting investigation..."
        )

        # -----------------------------------------------------
        # Mandatory initial alert retrieval
        # -----------------------------------------------------

        self.retrieve_initial_alert()

        print(
            "Initial alert retrieved."
        )

        # -----------------------------------------------------
        # Agentic investigation loop
        # -----------------------------------------------------

        for step in range(
            1,
            max_steps + 1
        ):

            print()
            print(
                f"Investigation step: {step}"
            )

            decision = self.decide_next_action()

            print()
            print(
                "LLM decision:"
            )

            print(
                json.dumps(
                    decision,
                    indent=2
                )
            )

            # -------------------------------------------------
            # Finish
            # -------------------------------------------------

            if decision["action"] == "finish":

                self.state.set_status(
                    "investigation_complete"
                )

                print()
                print(
                    "Investigation complete."
                )

                return

            # -------------------------------------------------
            # Execute tool
            # -------------------------------------------------

            tool_name = decision[
                "tool"
            ]

            arguments = decision[
                "arguments"
            ]

            print(
                f"Executing tool: {tool_name}"
            )

            result = self.execute(
                tool_name,
                arguments
            )

            if tool_name == "get_alert":
                self.state.set_alert(
                    result
                )

            print(
                f"Tool {tool_name} completed."
            )

        # -----------------------------------------------------
        # Step limit
        # -----------------------------------------------------

        self.state.set_status(
            "max_steps_reached"
        )

        print()
        print(
            f"Maximum investigation steps reached: "
            f"{max_steps}"
        )