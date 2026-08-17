import json

from agent.llm import LocalLLM
from agent.tool_registry import (TOOLS,execute_tool,get_tool_descriptions)
from state.investigation import InvestigationState
from state.result import InvestigationResult

class Investigator:

    # Evidence trimming for the LLM context only. The full,
    # untrimmed evidence always stays in InvestigationState for
    # the final report - these limits only shape what gets sent
    # to the model on each decision turn, since raw Wazuh events
    # (full_log, decoder, nested rule metadata) are large enough
    # to overflow a local model's context window within 1-2 tool
    # calls otherwise.
    DEFAULT_MAX_EVENTS_FOR_LLM = 8
    DEFAULT_MAX_STRING_LENGTH = 300

    def __init__(
        self,
        state: InvestigationState,
        max_steps: int = 10,
        max_decision_retries: int = 3,
        max_events_for_llm: int = DEFAULT_MAX_EVENTS_FOR_LLM,
        max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    ):
        self.state = state
        self.llm = LocalLLM()

        self.max_steps = max_steps
        self.max_decision_retries = max_decision_retries
        self.max_events_for_llm = max_events_for_llm
        self.max_string_length = max_string_length

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

    def _truncate_strings(self, value):
        """
        Recursively shorten any string longer than
        max_string_length. Wazuh full_log lines and some rule
        descriptions can be long enough on their own to matter.
        """

        if isinstance(value, str):
            if len(value) > self.max_string_length:
                return value[:self.max_string_length] + "...[truncated]"
            return value

        if isinstance(value, dict):
            return {
                key: self._truncate_strings(item)
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [
                self._truncate_strings(item)
                for item in value
            ]

        return value

    def _summarize_event(self, event):
        """
        Drop the raw full_log line from a single event/alert
        before it goes to the LLM. full_log duplicates
        information already present in the structured rule,
        decoder, and data fields, and is the single largest
        contributor to context bloat.

        The untouched original stays in InvestigationState -
        this only affects what the model sees.
        """

        if not isinstance(event, dict):
            return event

        trimmed = {
            key: value
            for key, value in event.items()
            if key != "full_log"
        }

        return self._truncate_strings(trimmed)

    def _summarize_tool_result(self, result):
        """
        Cap the number of events shown per tool result and strip
        bloat from each one. Tool results with an "events" list
        (search_wazuh_events, get_authentication_events,
        get_process_events) are capped at max_events_for_llm;
        the model is told when results were cut so it knows to
        narrow its time range instead of assuming it saw
        everything.
        """

        if not isinstance(result, dict):
            return result

        summarized = dict(result)

        events = summarized.get("events")

        if isinstance(events, list):

            visible_events = events[:self.max_events_for_llm]

            summarized["events"] = [
                self._summarize_event(event)
                for event in visible_events
            ]

            if len(events) > self.max_events_for_llm:
                summarized["note"] = (
                    f"Showing {self.max_events_for_llm} of "
                    f"{len(events)} matching events "
                    f"(count={summarized.get('count')}). "
                    "Narrow the time range for a more focused "
                    "view if needed."
                )

        evidence = summarized.get("evidence")

        if isinstance(evidence, dict):
            summarized["evidence"] = self._summarize_event(evidence)

        return summarized

    def _build_investigation_context(self):
        """
        Build a compact representation of the investigation
        state for the LLM.

        Tool results are kept in evidence, but summarized before
        being sent to the model (see _summarize_tool_result) so
        the context stays well within the configured num_ctx even
        across several investigation steps. Tool call history
        contains only metadata here to avoid duplicating large
        results a second time in the model context.
        """

        tool_history = []

        for call in self.state.tool_calls:

            tool_history.append({
                "tool": call.get("tool"),
                "arguments": call.get("arguments")
            })

        summarized_alert = self._summarize_event(self.state.alert)

        summarized_evidence = [
            self._summarize_tool_result(item)
            for item in self.state.evidence
        ]

        return json.dumps(
            {
                "incident_id": self.state.incident_id,

                "alert": summarized_alert,

                "evidence": summarized_evidence,

                "tool_calls": tool_history,

                "findings": self.state.findings
            },
            indent=2,
            default=str
        )

    # =========================================================
    # SYSTEM PROMPT
    # =========================================================

    def _build_example_decision(self):
        """
        Build a one-shot example decision from the real tool
        registry, so the example can never drift out of sync
        with the actual tool names or parameter names.

        A weak local model copies shape far more reliably than
        it follows abstract rules, so this example is the most
        important part of the prompt for correctness.
        """

        example_tool_name = "get_authentication_events"

        tool_definition = TOOLS.get(example_tool_name)

        if tool_definition is None:
            # Fall back to whatever the first non-get_alert tool is,
            # in case the registry changes in the future.
            example_tool_name = next(
                name for name in TOOLS if name != "get_alert"
            )
            tool_definition = TOOLS[example_tool_name]

        example_arguments = {}

        for parameter_name in tool_definition.get("required", []):
            if parameter_name == "agent_id":
                example_arguments[parameter_name] = "001"
            elif parameter_name == "start_time":
                example_arguments[parameter_name] = "2026-01-01T00:00:00Z"
            elif parameter_name == "end_time":
                example_arguments[parameter_name] = "2026-01-01T01:00:00Z"
            elif parameter_name == "alert_id":
                example_arguments[parameter_name] = "WJuiCqAB0yAL2NcCZXbq"
            else:
                example_arguments[parameter_name] = "example_value"

        tool_call_example = {
            "action": "tool",
            "tool": example_tool_name,
            "arguments": example_arguments
        }

        finish_example = {
            "action": "finish",
            "tool": None,
            "arguments": None
        }

        return tool_call_example, finish_example

    def _build_system_prompt(self):

        tool_descriptions = get_tool_descriptions()

        tool_names = list(TOOLS.keys())

        tool_call_example, finish_example = (
            self._build_example_decision()
        )

        return f"""
You are a SOC investigation agent.

You are investigating one Wazuh security alert.

Your task is to collect enough evidence to understand the
incident and then decide when the investigation can finish.

AVAILABLE TOOLS

The ONLY valid values for "tool" are exactly these strings:

{json.dumps(tool_names)}

Do not use any tool name that is not in this exact list. Do not
add prefixes, suffixes, or namespaces to a tool name.

Full tool definitions, including required parameter names:

{json.dumps(tool_descriptions, indent=2)}

RESPONSE FORMAT

You must respond with a single JSON object shaped exactly like
one of the two examples below. Copy the shape exactly. Do not
add extra keys. Do not wrap it in another object.

Example: calling a tool
{json.dumps(tool_call_example, indent=2)}

Example: finishing the investigation
{json.dumps(finish_example, indent=2)}

Notice in the tool-call example:
- "tool" is one of the exact strings from AVAILABLE TOOLS above.
- Every key inside "arguments" is one of that tool's exact
  parameter names shown in the tool definition. Nothing else.

INVESTIGATION RULES

1. Only use tools from the AVAILABLE TOOLS list above.

2. Never invent a tool name. Never invent an argument name.

3. Use exactly the parameter names defined for the selected tool,
   spelled exactly as shown in the tool definition.

4. Do not generate Wazuh DSL, OpenSearch queries, event_query
   objects, or arbitrary query structures.

5. search_wazuh_events returns broad event context for the
   specified agent and time range. Use it when broad context
   around the alert is useful.

6. get_authentication_events is available when authentication
   activity needs more focused investigation.

7. get_process_events is available when process or command
   execution activity needs more focused investigation.

8. The initial alert has already been retrieved. Do not call
   get_alert again.

9. Examine the alert and previously collected evidence before
   selecting another tool.

10. Do not finish after using only one investigative tool. Use
    at least two different tools (for example
    search_wazuh_events and get_authentication_events) before
    finishing, so the investigation is not based on a single
    narrow query.

11. Collect additional evidence when the current evidence does
    not adequately explain the incident.

12. Do not repeat the exact same tool call unless there is a
    specific investigative reason.

13. Do not invent timestamps, agent IDs, or alert IDs. Reuse
    values present in the investigation state whenever possible.

14. Finish when the available evidence is sufficient to form
    a reasonable security assessment.

15. Return only the JSON decision object. No explanation text,
    no markdown, no code fences.
"""

    # =========================================================
    # DECISION
    # =========================================================

    def _distinct_investigative_tools_used(self):
        """
        Set of tool names used so far, excluding get_alert.
        """

        return {
            call.get("tool")
            for call in self.state.tool_calls
            if call.get("tool") != "get_alert"
        }

    def _has_investigative_evidence(self):
        """
        True once at least two distinct tools other than
        get_alert have been called. Requiring more than one
        distinct tool (rather than just one call) pushes the
        model toward genuinely broadening its investigation
        instead of being satisfied with a single narrow query -
        a single search_wazuh_events call, for example, is not
        enough on its own to justify concluding the investigation.

        Shared by decide_next_action (to structurally block
        "finish" in the schema) and _validate_decision (as a
        defense-in-depth check), so there is exactly one
        definition of "has real investigation happened yet".
        """

        return len(self._distinct_investigative_tools_used()) >= 2

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
                allowed_tools=TOOLS.keys(),
                allow_finish=self._has_investigative_evidence()
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

            if not self._has_investigative_evidence():

                unused_tools = sorted(
                    set(TOOLS.keys())
                    - {"get_alert"}
                    - self._distinct_investigative_tools_used()
                )

                raise ValueError(
                    "Cannot finish yet. At least two distinct "
                    "investigative tools must be used first. "
                    "Tools not yet used: "
                    f"{unused_tools}"
                )

            # A "finish" decision must not also carry tool-call
            # content. The schema allows tool/arguments to be
            # null OR populated regardless of action, so this is
            # not caught by the JSON schema itself - the model
            # can blend the shape of a tool call into a finish
            # decision, and that must be rejected explicitly
            # rather than silently accepted as "finish".

            if decision.get("tool") is not None:
                raise ValueError(
                    "A 'finish' decision must have tool set to "
                    "null. Do not include a tool name when "
                    "finishing."
                )

            if decision.get("arguments") is not None:
                raise ValueError(
                    "A 'finish' decision must have arguments set "
                    "to null. Do not include arguments when "
                    "finishing."
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
    # FINAL INVESTIGATION RESULT
    # =========================================================

    def generate_investigation_result(self):
        """
        Generate the structured conclusion of the investigation.

        This is called only after the investigation loop decides
        that sufficient evidence has been collected.
        """

        messages = [
            {
                "role": "system",
                "content": """
You are the final analysis stage of a SOC investigation.

Review the Wazuh alert and all collected investigation evidence.

Produce a structured investigation result.

Important rules:

1. Base every finding on the supplied evidence.
2. Do not invent events, users, IP addresses, commands,
   timestamps, or attack activity.
3. Distinguish observed evidence from interpretation.
4. If the evidence does not establish something, state that
   clearly as a limitation.
5. Confidence must be a decimal between 0 and 1.
    Examples:
    0.95 = very high confidence
    0.75 = moderate-high confidence
    0.50 = uncertain
    0.20 = very low confidence
    Never use percentages such as 95 or 75.
6. Keep the conclusion concise and evidence-based.
7. Timeline entries must use timestamps present in the evidence.
8. Do not recommend response actions yet.
9. This stage is analysis only. Response decisions belong to
   a later stage.
10.Each finding must have exactly one type:

    observed:
    A fact directly present in the collected evidence.

    detection:
    A classification explicitly made by Wazuh or another
    security detection system.

    inference:
    An analyst conclusion derived from one or more observations
    or detections.

    Do not present an inference as an observed fact.
    Do not present a Wazuh detection classification as an
    independently verified fact.
11. Every factual finding must reference one or more supplied
    evidence IDs.

    Do not invent evidence IDs.

    Before writing a limitation, inspect the supplied evidence
    to determine whether the information actually exists.

Return only the JSON object matching the supplied schema.
"""
            },
            {
                "role": "user",
                "content": self._build_investigation_context()
            }
        ]

        schema = {
            "type": "object",

            "properties": {

                "summary": {
                    "type": "string",
                    "description": (
                        "A concise summary of what was established during "
                        "the investigation. Do not include unsupported claims."
                    )
                },

                "findings": {
                    "type": "array",
                    "description": (
                        "Evidence-grounded findings produced from the "
                        "investigation."
                    ),

                    "items": {
                        "type": "object",

                        "properties": {

                            "finding": {
                                "type": "string",
                                "description": (
                                    "A specific factual observation, Wazuh "
                                    "detection classification, or analyst "
                                    "inference."
                                )
                            },

                            "type": {
                                "type": "string",
                                "enum": [
                                    "observed",
                                    "detection",
                                    "inference"
                                ],
                                "description": (
                                    "observed = directly supported by an event; "
                                    "detection = explicitly classified by Wazuh; "
                                    "inference = analyst conclusion derived "
                                    "from evidence."
                                )
                            },

                            "evidence_ids": {
                                "type": "array",
                                "minItems": 1,
                                "items": {
                                    "type": "string"
                                },
                                "description": (
                                    "IDs of the collected evidence that directly "
                                    "support this finding."
                                )
                            },

                            "confidence": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 1,
                                "description": (
                                    "Confidence in this finding, represented "
                                    "as a decimal from 0.0 to 1.0."
                                )
                            }
                        },

                        "required": [
                            "finding",
                            "type",
                            "evidence_ids",
                            "confidence"
                        ],

                        "additionalProperties": False
                    }
                },

                "timeline": {
                    "type": "array",
                    "description": (
                        "Chronological sequence of significant events "
                        "observed during the investigation."
                    ),

                    "items": {
                        "type": "object",

                        "properties": {

                            "timestamp": {
                                "type": "string",
                                "description": (
                                    "Timestamp exactly as represented in the "
                                    "supporting evidence."
                                )
                            },

                            "event": {
                                "type": "string",
                                "description": (
                                    "Concise description of the event. "
                                    "Do not introduce information not present "
                                    "in the evidence."
                                )
                            },

                            "evidence_id": {
                                "type": "string",
                                "description": (
                                    "ID of the collected evidence corresponding "
                                    "to this timeline event."
                                )
                            }
                        },

                        "required": [
                            "timestamp",
                            "event",
                            "evidence_id"
                        ],

                        "additionalProperties": False
                    }
                },

                "conclusion": {
                    "type": "string",
                    "description": (
                        "Overall analyst conclusion based only on the "
                        "collected evidence and findings."
                    )
                },

                "confidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": (
                        "Overall confidence in the investigation conclusion, "
                        "represented as a decimal from 0.0 to 1.0."
                    )
                },

                "limitations": {
                    "type": "array",
                    "description": (
                        "Important uncertainties or information that could "
                        "not be established from the collected evidence."
                    ),

                    "items": {
                        "type": "string"
                    }
                }
            },

            "required": [
                "summary",
                "findings",
                "timeline",
                "conclusion",
                "confidence",
                "limitations"
            ],

            "additionalProperties": False
        }

        response = self.llm.generate_structured(
            messages,
            schema
        )

        print()
        print("RAW INVESTIGATION RESULT:")
        print(response)

        try:
            result = json.loads(response)

        except json.JSONDecodeError as exc:

            raise ValueError(
                "LLM produced invalid investigation result JSON."
            ) from exc

        self._validate_investigation_result(
            result
        )

        investigation_result = InvestigationResult(
            incident_id=self.state.incident_id,
            status="complete",
            summary=result["summary"],
            findings=result["findings"],
            timeline=result["timeline"],
            conclusion=result["conclusion"],
            confidence=result["confidence"],
            limitations=result["limitations"]
        )

        self.state.findings = (
            investigation_result.findings
        )

        self.state.set_final_report(
            investigation_result.to_dict()
        )

        return investigation_result

    def _validate_investigation_result(self,result):
        """
        Validate the final investigation result before it is
        accepted into InvestigationState.
        """

        if not isinstance(result, dict):
            raise ValueError(
                "Investigation result must be a JSON object."
            )
        finding_type = finding.get("type")

        if finding_type not in {"observed","detection","inference"}:
            raise ValueError( f"Invalid finding type: {finding_type}")

        required_fields = {
            "summary",
            "findings",
            "timeline",
            "conclusion",
            "confidence",
            "limitations"
        }

        missing = (
            required_fields
            - set(result.keys())
        )

        if missing:
            raise ValueError(
                "Investigation result is missing fields: "
                f"{sorted(missing)}"
            )

        if not isinstance(
            result["summary"],
            str
        ):
            raise ValueError(
                "Investigation summary must be a string."
            )

        if not isinstance(
            result["findings"],
            list
        ):
            raise ValueError(
                "Investigation findings must be a list."
            )

        if not isinstance(
            result["timeline"],
            list
        ):
            raise ValueError(
                "Investigation timeline must be a list."
            )

        if not isinstance(
            result["conclusion"],
            str
        ):
            raise ValueError(
                "Investigation conclusion must be a string."
            )

        confidence = result["confidence"]

        if not isinstance(
            confidence,
            (int, float)
        ):
            raise ValueError(
                "Investigation confidence must be numeric."
            )

        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "Investigation confidence must be between "
                "0 and 1."
            )

        if not isinstance(
            result["limitations"],
            list
        ):
            raise ValueError(
                "Investigation limitations must be a list."
            )

        for finding in result["findings"]:

            if not isinstance(
                finding,
                dict
            ):
                raise ValueError(
                    "Each finding must be an object."
                )

            required = {
                "finding",
                "evidence_ids",
                "confidence"
            }

            missing = (
                required
                - set(finding.keys())
            )

            if missing:
                raise ValueError(
                    "Finding is missing fields: "
                    f"{sorted(missing)}"
                )

            if not isinstance(
                finding["finding"],
                str
            ):
                raise ValueError(
                    "Finding text must be a string."
                )

            if not isinstance(
                finding["evidence_ids"],
                list
            ):
                raise ValueError(
                    "Finding evidence_ids must be a list."
                )

            finding_confidence = (
                finding["confidence"]
            )

            if not isinstance(
                finding_confidence,
                (int, float)
            ):
                raise ValueError(
                    "Finding confidence must be numeric."
                )

            if not 0.0 <= finding_confidence <= 1.0:
                raise ValueError(
                    "Finding confidence must be between 0 and 1."
                )

    # =========================================================
    # MAIN LOOP
    # =========================================================

    def run(self,max_steps=None):

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

                print()
                print(
                    "Investigation evidence collection complete."
                )

                print(
                    "Generating investigation result..."
                )

                result = (
                    self.generate_investigation_result()
                )

                self.state.set_status(
                    "investigation_complete"
                )

                print()
                print(
                    "Investigation complete."
                )

                print()
                print(
                    "Investigation result:"
                )

                print(
                    json.dumps(
                        result.to_dict(),
                        indent=2
                    )
                )

                return result

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