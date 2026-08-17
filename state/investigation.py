class InvestigationState:

    def __init__(self, incident_id: str):
        self.incident_id = incident_id

        # The original Wazuh alert
        self.alert = None

        # Evidence collected by investigation tools
        self.evidence = []

        # Record every tool invocation
        self.tool_calls = []

        # Agent-generated findings
        self.findings = []

        # Current investigation status
        self.status = "initialized"

        # Final report, populated when investigation ends
        self.final_report = None

    def set_alert(self, alert):
        self.alert = alert

    def add_evidence(self, evidence):
        self.evidence.append(evidence)

    def add_tool_call(self, tool_name, arguments, result):
        self.tool_calls.append({
            "tool": tool_name,
            "arguments": arguments,
            "result": result
        })

    def add_finding(self, finding):
        self.findings.append(finding)

    def set_status(self, status):
        self.status = status

    def set_final_report(self, report):
        self.final_report = report