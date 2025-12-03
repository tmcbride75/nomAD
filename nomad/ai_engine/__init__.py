"""
nomAD AI Engine Module
======================

LLM integration for enhanced analysis and explanations.

Components:
- llm_client.py: Abstraction layer for LLM API calls
- reasoner.py: Orchestrates prompts and parses responses

Design Philosophy:
- AI is optional - analysis works without it
- Supports multiple LLM providers (OpenAI, Anthropic, local)
- Prompts are carefully structured for consistent responses
- Response parsing handles malformed JSON gracefully
"""

from .llm_client import LLMClient
from .reasoner import AIReasoner

