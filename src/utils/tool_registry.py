"""
Simple Tool Registry
Replaces Portia's tool registry with a basic implementation
"""

from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod


class Tool(ABC):
    """Base class for tools"""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """Execute the tool with given parameters"""
        pass


class ToolRegistry:
    """Simple tool registry to replace Portia's tool system"""

    def __init__(self):
        self.tools: Dict[str, Tool] = {}

    def add_tool(self, tool: Tool):
        """Add a tool to the registry"""
        self.tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[Tool]:
        """Get a tool by name"""
        return self.tools.get(name)

    def list_tools(self) -> List[Dict[str, str]]:
        """List all available tools"""
        return [
            {"name": tool.name, "description": tool.description}
            for tool in self.tools.values()
        ]

    def update(self, other_registry):
        """Update this registry with tools from another registry"""
        if hasattr(other_registry, "tools"):
            for tool in other_registry.tools.values():
                self.add_tool(tool)
        elif isinstance(other_registry, list):
            for tool in other_registry:
                if isinstance(tool, Tool):
                    self.add_tool(tool)


# Example tool registry for compatibility
example_tool_registry = ToolRegistry()
