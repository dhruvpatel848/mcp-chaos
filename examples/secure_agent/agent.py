"""Demo agent with correct controls. Run: mcp-chaos attack --target examples/secure_agent/agent.py"""
from mcp_chaos.demo_agents.secure import main
import asyncio

asyncio.run(main())
