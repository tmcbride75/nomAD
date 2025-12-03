"""
LLM Client Module
=================

Abstraction layer for LLM API interactions.

Supports:
- OpenAI API (GPT-4, GPT-3.5)
- Anthropic API (Claude)
- Custom/local endpoints (compatible with OpenAI API format)

Design Decisions:
-----------------
1. Uses a common interface regardless of provider
2. Handles retries and rate limiting gracefully
3. Supports streaming for long responses
4. Includes token counting for cost estimation
"""

import json
import time
from typing import Optional, Generator
from dataclasses import dataclass

from ..config import LLMConfig


@dataclass
class LLMResponse:
    """Container for LLM response data.
    
    Attributes:
        content: The text content of the response
        model: Model that generated the response
        prompt_tokens: Number of tokens in the prompt
        completion_tokens: Number of tokens in the completion
        total_tokens: Total tokens used
        finish_reason: Why the generation stopped
        raw_response: Raw API response (for debugging)
    """
    content: str
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str = ""
    raw_response: Optional[dict] = None


class LLMClient:
    """Abstract client for LLM API interactions.
    
    Usage:
        client = LLMClient(config)
        
        # Simple completion
        response = client.complete("Analyze this AD environment...")
        print(response.content)
        
        # With system prompt
        response = client.complete(
            prompt="What are the risks?",
            system_prompt="You are an AD security expert."
        )
    
    The client handles:
    - API authentication
    - Request formatting
    - Response parsing
    - Error handling and retries
    """
    
    def __init__(self, config: LLMConfig):
        """Initialize the LLM client.
        
        Args:
            config: LLMConfig object with API settings
        """
        self.config = config
        self._client = None
        
        if config.enabled and config.api_key:
            self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize the appropriate client based on provider."""
        if self.config.provider == "openai":
            try:
                import openai
                
                if self.config.api_base:
                    self._client = openai.OpenAI(
                        api_key=self.config.api_key,
                        base_url=self.config.api_base
                    )
                else:
                    self._client = openai.OpenAI(api_key=self.config.api_key)
                    
            except ImportError:
                raise ImportError("openai library required. Install with: pip install openai")
                
        elif self.config.provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.config.api_key)
            except ImportError:
                raise ImportError("anthropic library required. Install with: pip install anthropic")
    
    @property
    def is_available(self) -> bool:
        """Check if the LLM client is properly configured."""
        return self.config.enabled and self._client is not None
    
    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        json_mode: bool = False
    ) -> LLMResponse:
        """Send a completion request to the LLM.
        
        Args:
            prompt: The user prompt/query
            system_prompt: Optional system prompt for context
            temperature: Override default temperature
            max_tokens: Override default max tokens
            json_mode: Request JSON-formatted response
            
        Returns:
            LLMResponse object with the completion
            
        Raises:
            RuntimeError: If the client is not available
        """
        if not self.is_available:
            raise RuntimeError("LLM client not available. Check configuration and API key.")
        
        temperature = temperature or self.config.temperature
        max_tokens = max_tokens or self.config.max_tokens
        
        if self.config.provider == "openai":
            return self._complete_openai(prompt, system_prompt, temperature, max_tokens, json_mode)
        elif self.config.provider == "anthropic":
            return self._complete_anthropic(prompt, system_prompt, temperature, max_tokens)
        else:
            # Default to OpenAI-compatible
            return self._complete_openai(prompt, system_prompt, temperature, max_tokens, json_mode)
    
    def _complete_openai(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int,
        json_mode: bool
    ) -> LLMResponse:
        """OpenAI-specific completion."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        kwargs = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        
        # Retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self._client.chat.completions.create(**kwargs)
                
                return LLMResponse(
                    content=response.choices[0].message.content,
                    model=response.model,
                    prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
                    completion_tokens=response.usage.completion_tokens if response.usage else 0,
                    total_tokens=response.usage.total_tokens if response.usage else 0,
                    finish_reason=response.choices[0].finish_reason,
                    raw_response=response.model_dump()
                )
                
            except Exception as e:
                if attempt < max_retries - 1:
                    # Exponential backoff
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                else:
                    raise RuntimeError(f"OpenAI API error after {max_retries} attempts: {e}")
    
    def _complete_anthropic(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> LLMResponse:
        """Anthropic-specific completion."""
        kwargs = {
            "model": self.config.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        # Retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self._client.messages.create(**kwargs)
                
                content = ""
                for block in response.content:
                    if hasattr(block, 'text'):
                        content += block.text
                
                return LLMResponse(
                    content=content,
                    model=response.model,
                    prompt_tokens=response.usage.input_tokens if response.usage else 0,
                    completion_tokens=response.usage.output_tokens if response.usage else 0,
                    total_tokens=(response.usage.input_tokens + response.usage.output_tokens) if response.usage else 0,
                    finish_reason=response.stop_reason,
                    raw_response={"id": response.id, "model": response.model}
                )
                
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                else:
                    raise RuntimeError(f"Anthropic API error after {max_retries} attempts: {e}")
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate the number of tokens in a text string.
        
        Uses a simple heuristic: ~4 characters per token.
        
        Args:
            text: Text to estimate tokens for
            
        Returns:
            Estimated token count
        """
        # Simple heuristic - can be replaced with tiktoken for accuracy
        return len(text) // 4
    
    def test_connection(self) -> bool:
        """Test if the LLM connection is working.
        
        Returns:
            True if connection successful, False otherwise
        """
        if not self.is_available:
            return False
        
        try:
            response = self.complete(
                prompt="Say 'test successful' and nothing else.",
                max_tokens=20
            )
            return "test" in response.content.lower() or "successful" in response.content.lower()
        except Exception:
            return False

