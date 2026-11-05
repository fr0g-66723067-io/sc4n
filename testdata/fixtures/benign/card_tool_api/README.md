---
license: apache-2.0
---
# Tiny Tool Model

A small model with function calling.

```python
response = client.chat.completions.create(model=model, messages=messages, tools=tools)
tool_calls = response.choices[0].message.tool_calls
for tool_call in tool_calls:
    function_name = tool_call.function.name
    function_args = tool_call.function.arguments
```

## License

You must not use this model in a manner that infringes, misappropriates or otherwise violates any third party's rights, including intellectual property rights.
