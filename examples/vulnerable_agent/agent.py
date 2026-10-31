"""Deliberately vulnerable demo agent. Run: mcp-chaos attack --target examples/vulnerable_agent/agent.py"""
from mcp_chaos.demo_agents.vulnerable import main
import asyncio

asyncio.run(main())
