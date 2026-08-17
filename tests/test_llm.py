from agent.llm import LocalLLM


llm = LocalLLM()

messages = [
    {
        "role": "system",
        "content": "You are a cybersecurity investigation assistant."
    },
    {
        "role": "user",
        "content": "Explain what an SSH brute-force attack is in two sentences."
    }
]


result = llm.generate(messages)

print("LLM response:")
print(result)