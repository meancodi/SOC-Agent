import requests


class LocalLLM:

    def __init__(
        self,
        model: str = "llama3.2:3b",
        base_url: str = "http://localhost:11434"
    ):
        self.model = model
        self.base_url = base_url

    def generate(self, messages):

        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False
            },
            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        return data["message"]["content"]

    def decide(
        self,
        messages,
        allowed_tools=None
    ):
        """
        Ask the local model for a structured investigation decision.

        allowed_tools is supplied by the tool registry so the LLM
        interface does not maintain a second list of tool names.
        """

        if allowed_tools is None:
            allowed_tools = []

        tool_enum = list(allowed_tools) + [None]

        schema = {
            "type": "object",

            "properties": {

                "action": {
                    "type": "string",
                    "enum": [
                        "tool",
                        "finish"
                    ]
                },

                "tool": {
                    "type": [
                        "string",
                        "null"
                    ],
                    "enum": tool_enum
                },

                "arguments": {
                    "type": [
                        "object",
                        "null"
                    ]
                }
            },

            "required": [
                "action",
                "tool",
                "arguments"
            ],

            "additionalProperties": False
        }

        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False,
                "format": schema
            },
            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        return data["message"]["content"]