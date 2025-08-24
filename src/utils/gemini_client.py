"""
Gemini API Client Wrapper
Replaces Portia AI functionality with direct Gemini API calls
"""

import os
import json
from typing import Dict, Any, List, Optional
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class GeminiClient:
    """
    Wrapper for Google's Gemini API to replace Portia AI functionality
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-1.5-flash"):
        """Initialize Gemini client"""
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")

        # Configure Gemini
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(model)
        self.chat = None

    def run(
        self, prompt: str, tools: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Run a prompt through Gemini API
        Returns a result object similar to Portia's format
        """
        try:
            # If tools are provided, use them in the prompt
            if tools:
                tool_descriptions = "\n".join(
                    [
                        f"Tool: {tool.get('name', 'Unknown')} - {tool.get('description', 'No description')}"
                        for tool in tools
                    ]
                )
                enhanced_prompt = f"{prompt}\n\nAvailable tools:\n{tool_descriptions}"
            else:
                enhanced_prompt = prompt

            # Generate response
            response = self.model.generate_content(enhanced_prompt)

            # Format response to match Portia's expected structure
            result = {
                "state": "COMPLETE",
                "final_output": {
                    "response": response.text,
                    "prompt": prompt,
                    "model": self.model.model_name,
                },
                "error": None,
            }

            return result

        except Exception as e:
            return {"state": "ERROR", "final_output": None, "error": str(e)}

    def chat_run(
        self, message: str, tools: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Run a chat message through Gemini API
        Maintains conversation context
        """
        try:
            if self.chat is None:
                self.chat = self.model.start_chat(history=[])

            # If tools are provided, use them in the message
            if tools:
                tool_descriptions = "\n".join(
                    [
                        f"Tool: {tool.get('name', 'Unknown')} - {tool.get('description', 'No description')}"
                        for tool in tools
                    ]
                )
                enhanced_message = f"{message}\n\nAvailable tools:\n{tool_descriptions}"
            else:
                enhanced_message = message

            # Send message and get response
            response = self.chat.send_message(enhanced_message)

            # Format response to match Portia's expected structure
            result = {
                "state": "COMPLETE",
                "final_output": {
                    "response": response.text,
                    "message": message,
                    "model": self.model.model_name,
                },
                "error": None,
            }

            return result

        except Exception as e:
            return {"state": "ERROR", "final_output": None, "error": str(e)}

    def reset_chat(self):
        """Reset the chat conversation"""
        self.chat = None

    def get_available_models(self) -> List[str]:
        """Get list of available Gemini models"""
        try:
            models = genai.list_models()
            return [
                model.name
                for model in models
                if "generateContent" in model.supported_generation_methods
            ]
        except Exception:
            return ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"]
