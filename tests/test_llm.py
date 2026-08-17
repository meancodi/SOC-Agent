from agent.llm import LocalLLM


llm = LocalLLM()

messages = [
    {
        "role": "system",
        "content": "You are an educational instructor who needs to tell users what your name and specifications are accurately. Do NOT lie."
    },
    {
        "role": "user",
        "content": "What's your model name like llama, mistral, etc.? How many parameters do you have?"
    }
]


result = llm.generate(messages)

print("LLM response:")
print(result)