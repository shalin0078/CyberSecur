import os
from openai import OpenAI
import streamlit as st

# Configuration
API_KEY = "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"
BASE_URL = "https://openrouter.ai/api/v1"

class ChatbotManager:
    def __init__(self):
        self.client = OpenAI(
            api_key=API_KEY,
            base_url=BASE_URL
        )
        self.model = "google/gemini-2.0-flash-001"

    def generate_response(self, messages, context=None):
        """
        Generate a response from the AI model.
        
        Args:
            messages (list): List of message dicts [{'role': 'user', 'content': '...'}, ...]
            context (dict): Optional dictionary of current system status to inject.
        """
        
        system_prompt = """You are an expert Cybersecurity Incident Manager and AI SOC Analyst.
Your role is to assist security teams by providing real-time updates, guiding response steps, and answering technical questions.

You have access to the following real-time system telemetry:
{context_str}

GUIDELINES:
1. Be concise, professional, and action-oriented.
2. If an intrusion is detected, prioritize immediate containment steps.
3. Use bullet points for steps or playbooks.
4. If asked about specific attacks (e.g., 'Neptune', 'Smurf'), explain them briefly and suggest mitigation.
5. Maintain a 'Command Center' persona.
"""
        
        # Format context string
        context_str = "No specific telemetry available."
        if context:
            context_str = "\n".join([f"- {k}: {v}" for k, v in context.items()])

        # Prepend system message
        full_messages = [
            {"role": "system", "content": system_prompt.format(context_str=context_str)}
        ] + messages

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=full_messages,
                extra_headers={
                    "HTTP-Referer": "http://localhost:8501", # Required by OpenRouter
                    "X-Title": "CyberSecure Dashboard",
                }
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"⚠️ **System Error**: Unable to contact AI Command Center. \n\n*Debug Info*: {str(e)}"
