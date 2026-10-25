from google.adk.agents import Agent
from google.adk.code_executors import BuiltInCodeExecutor
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset

ops_agent = Agent(
    name="ops",
    tools=[BuiltInCodeExecutor, MCPToolset],
)
