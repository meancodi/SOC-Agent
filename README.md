# AI SOC Security Investigation Agent

An Agentic AI based Security Operations Center investigation system that uses **Wazuh as the SIEM** and a **single AI SOC agent** to investigate security alerts through controlled tool calls.

The project is designed to demonstrate practical **Agentic AI**, rather than simply connecting an LLM to a prompt and generating a response.

## Project Status

**Current stage: MVP investigation loop implemented and tested**

The Wazuh integration and investigation tests are currently working successfully. The project has moved beyond the initial Wazuh setup and is now at the stage of integrating and validating the agentic investigation workflow.

### Current progress

| Component                       | Status                      |
| ------------------------------- | --------------------------- |
| Wazuh SIEM                      | Complete                    |
| Monitored endpoint              | Complete                    |
| Security alert generation       | Complete                    |
| Wazuh API integration           | Complete                    |
| Python Wazuh integration        | Complete                    |
| Investigation tools             | Complete                    |
| Initial investigation workflow  | Complete                    |
| Investigation tests             | Passing                     |
| Single SOC AI agent             | In progress / current focus |
| Multi-step tool calling         | In progress / current focus |
| Evidence correlation            | In progress                 |
| Structured investigation report | In progress                 |
| Multiple security scenarios     | Planned                     |
| MITRE ATT&CK mapping            | Optional                    |
| Threat intelligence             | Optional                    |
| Streamlit UI                    | Optional                    |

The immediate goal is to complete and validate the **single-agent multi-step investigation loop** before adding optional features.

## Objective

Build a working AI SOC Security Investigation Agent that behaves similarly to a junior SOC analyst.

The system receives a Wazuh security alert and should:

1. Understand the initial alert.
2. Determine what is already known.
3. Identify missing evidence.
4. Select an appropriate investigation tool.
5. Execute the tool.
6. Observe the returned evidence.
7. Update its investigation state.
8. Decide whether additional evidence is required.
9. Perform additional tool calls when necessary.
10. Correlate the collected evidence.
11. Assess severity and confidence.
12. Produce a structured investigation report.

The core principle is:

```text
Security Event
      ↓
    Wazuh
      ↓
 Wazuh Alert
      ↓
    Python
      ↓
 Single SOC Agent
      ↓
 Investigation Tools
      ↓
 Wazuh Evidence
      ↓
 Evidence Correlation
      ↓
 Risk Assessment
      ↓
 Investigation Report
      ↓
 Human Review
```

This architecture keeps **security telemetry and detection in Wazuh**, while the **AI agent performs investigation, reasoning, and evidence correlation**.

## Why This Is Agentic AI

The system is intentionally not designed as:

```text
Alert → LLM → Report
```

That would largely be an LLM wrapper.

Instead, the agent should operate iteratively:

```text
Alert
  ↓
Analyze known information
  ↓
Identify missing evidence
  ↓
Select tool
  ↓
Execute tool
  ↓
Observe result
  ↓
Update investigation
  ↓
Need more evidence?
  ├── Yes → Select another tool
  │          ↓
  │        Execute
  │          ↓
  │        Observe
  │          ↓
  │        Update
  │
  └── No
       ↓
  Correlate evidence
       ↓
  Assess incident
       ↓
  Generate report
```

This introduces the important Agentic AI concepts the project is intended to demonstrate:

* Agents
* Tool calling
* Agent loops
* State
* Planning
* Observation
* Iterative reasoning
* Structured outputs
* Guardrails
* Human-in-the-loop
* Agent evaluation
* Tracing

## Current Architecture

### SIEM Layer

**Wazuh**

Wazuh is responsible for:

* Collecting endpoint telemetry
* Detecting security events
* Generating alerts
* Providing security event data through its API

### Integration Layer

**Python**

Python provides the controlled interface between the AI agent and Wazuh.

The LLM should not directly manipulate the Wazuh API.

Instead:

```text
AI Agent
   ↓
Python Tool
   ↓
Wazuh API
   ↓
Security Data
   ↓
Python Tool Result
   ↓
AI Agent
```

This provides a controlled boundary around external system access.

### Agent Layer

The MVP uses **one AI SOC investigation agent**.

The agent is responsible for deciding:

* What evidence is currently available
* What evidence is missing
* Which tool should be called
* Whether another investigation step is required
* When sufficient evidence has been collected
* What conclusion can reasonably be drawn

The initial agent framework is planned around the **OpenAI Agents SDK**, while keeping the model provider replaceable.

### Investigation Tools

The initial toolset consists of:

```text
get_alert()
search_wazuh_events()
get_authentication_events()
get_process_events()
```

Optional tools can later include:

```text
lookup_ip()
lookup_hash()
lookup_mitre_technique()
```

The toolset is intentionally small for the MVP.

## Current Investigation Flow

The current implementation has already established the basic Wazuh retrieval and investigation infrastructure.

The test workflow successfully reaches the investigation stage and retrieves a real alert.

A representative flow is:

```text
Starting investigation...

Retrieving initial alert...
Alert ID: <Wazuh Alert ID>
Initial alert retrieved.

Investigation step: 1
...
```

The Wazuh alert retrieval and investigation tests are currently passing.

The next development objective is to connect the successful Wazuh investigation layer to the AI agent so that the agent itself controls the investigation sequence through tool calls.

## Planned Investigation State

The investigation should maintain state throughout the agent loop.

Conceptually:

```python
investigation_state = {
    "alert": ...,
    "known_evidence": [...],
    "missing_evidence": [...],
    "tool_calls": [...],
    "hypothesis": ...,
    "severity": ...,
    "confidence": ...,
    "mitre_techniques": [...],
    "limitations": [...]
}
```

The exact implementation can evolve as the agent is developed.

The important requirement is that information collected from one tool call must remain available to subsequent investigation steps.

## Security Scenarios

The MVP should be evaluated against multiple controlled scenarios.

### 1. Multiple Failed Authentication Attempts

Example:

```text
User
  ↓
Multiple failed logins
  ↓
Wazuh Alert
  ↓
Agent investigates authentication events
  ↓
Determines whether the pattern is suspicious
```

### 2. Failed Authentication Followed by Successful Authentication

This scenario is particularly useful because the sequence contains more information than an isolated failed login.

Expected investigation:

```text
Failed authentication
        ↓
Additional authentication evidence
        ↓
Successful authentication
        ↓
Temporal correlation
        ↓
Security hypothesis
```

### 3. Suspicious Process Execution

The agent should investigate process-related evidence and determine whether the process execution is consistent with suspicious activity.

### 4. Benign Authentication Activity

A benign scenario is required to prevent the agent from treating every unusual event as malicious.

The evaluation should therefore include both:

```text
Malicious / suspicious scenarios
```

and:

```text
Benign scenarios
```

## Investigation Report

The final investigation output should contain:

```text
Incident ID
Severity
Confidence
Affected Host
Affected User
Attack Hypothesis
Evidence
MITRE ATT&CK Techniques
Recommended Actions
Limitations / Missing Evidence
```

A critical requirement is the distinction between **observed evidence** and **AI interpretation**.

For example:

```text
Observed Evidence:
- Multiple failed authentication attempts
- Successful authentication from the same source
- Process execution observed after authentication

AI Interpretation:
- The sequence is consistent with a possible credential compromise scenario.
```

The agent must not present an inference as if it were directly observed telemetry.

If the available evidence is insufficient, the report should explicitly state that.

## Safety Model

The system is intended for use inside an isolated and authorized security lab.

The MVP must not perform unauthorized activity against external systems.

The AI agent should also not autonomously perform destructive response actions such as:

* Disabling accounts
* Killing processes
* Blocking infrastructure
* Deleting files
* Modifying security infrastructure

The intended architecture is:

```text
AI Investigation
      ↓
Recommendation
      ↓
Human Review
      ↓
Approved Response
```

High-impact actions should require explicit human approval.

## Technology Stack

| Component            | Technology                  |
| -------------------- | --------------------------- |
| SIEM                 | Wazuh                       |
| Programming Language | Python                      |
| Agent Framework      | OpenAI Agents SDK           |
| LLM                  | Replaceable model provider  |
| SIEM Integration     | Wazuh API                   |
| Threat Intelligence  | Optional free/public source |
| ATT&CK Mapping       | MITRE ATT&CK                |
| Testing              | pytest                      |
| UI                   | Streamlit, optional         |
| Storage              | JSON / simple files         |
| Version Control      | Git / GitHub                |
| Containerization     | Docker, optional            |

## Development Strategy

The project is being developed incrementally.

The implementation should not attempt to build the entire system at once.

The development sequence is:

```text
1. Wazuh Setup
      ↓
2. Endpoint Telemetry
      ↓
3. Wazuh Alerts
      ↓
4. Wazuh API
      ↓
5. Python Integration
      ↓
6. Investigation Tools
      ↓
7. Tool Testing
      ↓
8. Single AI Agent
      ↓
9. Tool Calling
      ↓
10. Investigation Loop
      ↓
11. Evidence Correlation
      ↓
12. Structured Output
      ↓
13. Scenario Testing
      ↓
14. Evaluation
```

Each major component should be independently tested before moving to the next stage.

## Testing Strategy

Testing should cover both individual components and complete investigations.

### Unit / Component Testing

Examples:

```text
Wazuh API connection
Alert retrieval
Event search
Authentication event retrieval
Process event retrieval
Tool input validation
Tool output handling
Structured output validation
```

### Agent Testing

The agent should be tested for:

* Correct tool selection
* Multiple tool calls when necessary
* Correct use of previous evidence
* Appropriate stopping decisions
* Evidence-grounded conclusions
* Correct severity assessment
* Confidence assessment
* Avoidance of fabricated evidence

### Scenario Testing

Each security scenario should have a reproducible test environment and expected investigation characteristics.

The agent should not be evaluated solely on whether its final text "sounds correct."

Evaluation should consider whether it:

1. Retrieved relevant evidence.
2. Used the correct tools.
3. Performed sufficient investigation.
4. Avoided unsupported conclusions.
5. Produced the expected structured output.

## Debugging Method

When something fails, debug by layer.

```text
1. Identify the failing layer
        ↓
2. Reproduce the problem
        ↓
3. Test that layer independently
        ↓
4. Fix the underlying issue
        ↓
5. Verify the fix
        ↓
6. Continue development
```

Avoid modifying several components simultaneously without identifying the source of the failure.

## MVP Completion Criteria

The MVP is considered complete when the following workflow works reliably:

```text
Controlled Security Event
        ↓
Wazuh Detection
        ↓
Wazuh Alert
        ↓
Python Alert Retrieval
        ↓
AI SOC Agent
        ↓
Tool Call
        ↓
Wazuh Investigation
        ↓
Evidence Returned
        ↓
Agent Updates Investigation
        ↓
Additional Tool Call
        ↓
Evidence Correlation
        ↓
Severity + Confidence
        ↓
Structured Investigation Report
```

The agent must demonstrate genuine multi-step investigation rather than a single LLM response.

## Optional Features After MVP

Only after the core investigation loop is reliable should the following be considered:

### Threat Intelligence

Integrate one free/public threat intelligence provider.

Potential investigations:

```text
IP → Threat Intelligence
Hash → Threat Intelligence
Domain → Threat Intelligence
```

### MITRE ATT&CK

Map investigation findings to relevant ATT&CK techniques.

### Streamlit

A lightweight UI could display:

```text
Alert
  ↓
Investigation Steps
  ↓
Tool Calls
  ↓
Collected Evidence
  ↓
Agent Reasoning Summary
  ↓
Final Assessment
```

The UI is secondary to the investigation engine.

## Features Explicitly Out of MVP Scope

The following should not be added merely for complexity:

* Multi-agent architecture
* Autonomous destructive response
* PostgreSQL
* Redis
* Kubernetes
* Complex RAG
* Complex long-term memory
* Cloud deployment
* React frontend
* Complex SOAR infrastructure
* Multiple threat intelligence providers

The objective is to make the **single-agent investigation loop reliable and explainable**.

## Development Environment

The current development machine provides:

```text
CPU:      Intel Core i7-13700HX
GPU:      NVIDIA RTX 4060 Mobile, 8 GB VRAM
RAM:      16 GB DDR5 5600 MHz
Storage:  512 GB SSD + 1 TB SSD
OS:       Windows 11 25H2
VM:       VirtualBox available
```

The 1 TB SSD is the preferred location for large VM or security-lab data because the 512 GB Windows SSD is nearly full.

## Project Philosophy

The project prioritizes:

1. Correct architecture
2. Real security telemetry
3. Real tool calls
4. Multi-step investigation
5. Evidence-grounded reasoning
6. Clear separation of evidence and inference
7. Reproducible testing
8. Measurable evaluation
9. Understandable implementation

A reliable investigation engine is more important than a sophisticated UI.

The final implementation should be explainable technically in an interview, including:

* Why Wazuh is used
* Why the LLM does not directly access Wazuh
* What makes the system agentic
* How tools are selected
* How investigation state is maintained
* How evidence is correlated
* How the agent knows when to stop
* How hallucinated evidence is prevented
* How the system is evaluated
* Where human approval is required

## Current Next Step

The immediate milestone is:

```text
Successful Wazuh Investigation Tools
              ↓
        Single AI Agent
              ↓
       Tool Calling
              ↓
      Multi-Step Loop
              ↓
    Structured Investigation
```

The priority should therefore be to implement and test the **single-agent investigation loop** before adding threat intelligence, MITRE automation, databases, UI, or multi-agent functionality.
