import requests


class LocalLLM:
    """
    Thin client around a local Ollama server.

    Two responsibilities only:
    - send chat messages, get back plain text (generate)
    - send chat messages, get back a schema-constrained JSON
      investigation decision (decide)

    All context-window and sampling behavior lives here so the
    investigator layer never has to know about Ollama specifics.
    """

    def __init__(
        self,
        model: str = "qwen2.5:7b-instruct",
        base_url: str = "http://localhost:11434",
        num_ctx: int = 8192,
        temperature: float = 0.0,
        timeout: int = 120
    ):
        self.model = model
        self.base_url = base_url
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.timeout = timeout

    # =========================================================
    # INTERNAL REQUEST HELPER
    # =========================================================

    def _chat(self, messages, format_schema=None):
        """
        Shared request path for both generate() and decide().

        Centralizing this means num_ctx / temperature / timeout
        are always applied consistently, and there is exactly one
        place in the codebase that talks HTTP to Ollama.

        Without an explicit "options.num_ctx", Ollama silently
        truncates the oldest messages once the default context
        window (4096 tokens on current Ollama versions) is
        exceeded - with no error and no warning. Wazuh evidence
        dumps blow past that almost immediately, so this must
        always be set explicitly rather than left to the default.
        """

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_ctx": self.num_ctx,
                "temperature": self.temperature
            }
        }

        if format_schema is not None:
            payload["format"] = format_schema

        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"Failed to reach Ollama at {self.base_url}: {exc}"
            ) from exc

        data = response.json()

        message = data.get("message")

        if not message or "content" not in message:
            raise RuntimeError(
                f"Unexpected Ollama response shape: {data}"
            )

        return message["content"]

    # =========================================================
    # PLAIN TEXT GENERATION
    # =========================================================

    def generate(self, messages):
        """
        Ask the model for free-form text, e.g. a final
        investigation report.
        """

        return self._chat(messages)

    # =========================================================
    # STRUCTURED INVESTIGATION DECISION
    # =========================================================

    def decide(
        self,
        messages,
        allowed_tools=None,
        allow_finish=True
    ):
        """
        Ask the local model for a structured investigation decision.

        allowed_tools is supplied by the tool registry so the LLM
        interface does not maintain a second list of tool names.

        allow_finish controls whether "finish" is even a legal
        value in the schema. Enforcing this structurally - instead
        of only through a prompt rule plus post-hoc validation and
        a retry - means the model cannot select "finish" too early
        no matter what it generates, because the token simply
        isn't part of the constrained grammar.

        The schema is built as a "oneOf" between exactly two
        shapes - a finish decision and a tool-call decision -
        rather than one flat object with independently-nullable
        "tool" / "arguments" fields. A flat schema only constrains
        each field on its own; it never says the two shapes are
        mutually exclusive, so a model can still blend them (e.g.
        action: "finish" with a populated "tool" field) even
        though each individual field value was valid in isolation.
        oneOf closes that gap at the schema level instead of
        relying on post-hoc validation and a retry to catch it.
        """

        if allowed_tools is None:
            allowed_tools = []

        tool_names = list(allowed_tools)

        tool_call_shape = {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "const": "tool"
                },
                "tool": {
                    "type": "string",
                    "enum": tool_names
                },
                "arguments": {
                    "type": "object"
                }
            },
            "required": [
                "action",
                "tool",
                "arguments"
            ],
            "additionalProperties": False
        }

        finish_shape = {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "const": "finish"
                },
                "tool": {
                    "type": "null"
                },
                "arguments": {
                    "type": "null"
                }
            },
            "required": [
                "action",
                "tool",
                "arguments"
            ],
            "additionalProperties": False
        }

        shapes = (
            [tool_call_shape, finish_shape]
            if allow_finish
            else [tool_call_shape]
        )

        schema = (
            shapes[0]
            if len(shapes) == 1
            else {"oneOf": shapes}
        )

        return self._chat(messages, format_schema=schema)