from tools.alerts import get_alert
from tools.events import search_wazuh_events
from tools.authentication import get_authentication_events
from tools.processes import get_process_events


TOOLS = {

    "get_alert": {
        "function": get_alert,
        "description": (
            "Retrieve a specific Wazuh alert using its alert ID."
        ),
        "parameters": {
            "alert_id": {
                "type": "string",
                "description": "The Wazuh alert ID."
            }
        },
        "required": [
            "alert_id"
        ]
    },

    "search_wazuh_events": {
        "function": search_wazuh_events,
        "description": (
            "Search all Wazuh events for a specific agent "
            "within a specified time range. Use this to "
            "collect broad context around a security alert."
        ),
        "parameters": {
            "agent_id": {
                "type": "string",
                "description": "Wazuh agent ID."
            },
            "start_time": {
                "type": "string",
                "description": (
                    "Start of the investigation window "
                    "in ISO-8601 format."
                )
            },
            "end_time": {
                "type": "string",
                "description": (
                    "End of the investigation window "
                    "in ISO-8601 format."
                )
            }
        },
        "required": [
            "agent_id",
            "start_time",
            "end_time"
        ]
    },

    "get_authentication_events": {
        "function": get_authentication_events,
        "description": (
            "Retrieve authentication-related Wazuh events "
            "for an agent within a specified time range."
        ),
        "parameters": {
            "agent_id": {
                "type": "string",
                "description": "Wazuh agent ID."
            },
            "start_time": {
                "type": "string",
                "description": (
                    "Start of the investigation window "
                    "in ISO-8601 format."
                )
            },
            "end_time": {
                "type": "string",
                "description": (
                    "End of the investigation window "
                    "in ISO-8601 format."
                )
            }
        },
        "required": [
            "agent_id",
            "start_time",
            "end_time"
        ]
    },

    "get_process_events": {
        "function": get_process_events,
        "description": (
            "Retrieve process and command execution events "
            "for an agent within a specified time range."
        ),
        "parameters": {
            "agent_id": {
                "type": "string",
                "description": "Wazuh agent ID."
            },
            "start_time": {
                "type": "string",
                "description": (
                    "Start of the investigation window "
                    "in ISO-8601 format."
                )
            },
            "end_time": {
                "type": "string",
                "description": (
                    "End of the investigation window "
                    "in ISO-8601 format."
                )
            }
        },
        "required": [
            "agent_id",
            "start_time",
            "end_time"
        ]
    }
}


def execute_tool(tool_name: str, arguments: dict):

    if tool_name not in TOOLS:
        raise ValueError(
            f"Unknown tool: {tool_name}"
        )

    function = TOOLS[tool_name]["function"]

    return function(**arguments)


def get_tool_descriptions():

    descriptions = {}

    for name, tool in TOOLS.items():

        descriptions[name] = {
            "description": tool["description"],
            "parameters": tool["parameters"],
            "required": tool["required"]
        }

    return descriptions