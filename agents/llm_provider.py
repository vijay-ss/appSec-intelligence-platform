"""
LLM Provider Abstraction
========================
All agents import from this module. No agent imports directly from
langchain_ollama, langchain_anthropic, or langchain_groq.

Three providers are supported:

  ollama    — local inference via Ollama (default, no API key needed)
              Good for: development, air-gapped environments
              Model: qwen2.5-coder:7b-instruct-q4_K_M (~4.5GB RAM)

  groq      — remote inference via Groq Cloud (free tier, off-laptop)
              Good for: development without local GPU, saving laptop RAM
              Models: llama-3.3-70b-versatile, mixtral-8x7b-32768, gemma2-9b-it
              Sign up free: https://console.groq.com
              Note: Groq does not provide an embeddings API — when using
              Groq as the LLM provider, embeddings fall back to Ollama
              (local) or OpenAI depending on EMBEDDING_PROVIDER.

  anthropic — remote inference via Anthropic API (paid, production quality)
              Good for: production deployments
              Model: claude-sonnet-4-5-20251001
              Embeddings: OpenAI text-embedding-3-large (OPENAI_API_KEY required)

Switching providers requires only a .env change — no code changes:
  LLM_PROVIDER=groq        # switch to Groq
  LLM_PROVIDER=anthropic   # switch to Anthropic
  LLM_PROVIDER=ollama      # back to local
"""
import os
from langchain_core.language_models import BaseChatModel
from langchain_core.embeddings import Embeddings

def get_llm(temperature: float=0.0) -> BaseChatModel:
    """Return the configured chat model."""
    provider = os.getenv("LLM_PROVIDER", "ollama")
    
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b-instruct-q4_K_M"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            temperature=temperature,
        )
    
    if provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            api_key=os.getenv("GROQ_API_KEY"),
            temperature=temperature,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20251001"),
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            temperature=temperature,
        )
    
    raise ValueError(
        f"Unknown LLM_PROVIDER: {provider!r} — use 'ollama', 'groq', or 'anthropic'"
    )


def get_embeddings() -> Embeddings:
    """
    Return the configured embeddings model.

    Embeddings are controlled by EMBEDDING_PROVIDER independently of LLM_PROVIDER.
    This matters for Groq: Groq has no embeddings API, so you can use
    LLM_PROVIDER=groq for chat while keeping EMBEDDING_PROVIDER=ollama for embeddings.

    EMBEDDING_PROVIDER options:
      ollama  — nomic-embed-text via local Ollama (default)
      openai  — text-embedding-3-large via OpenAI API (requires OPENAI_API_KEY)
    """
    embedding_provider = os.getenv("EMBEDDING_PROVIDER", "ollama")

    if embedding_provider == "ollama":
        from langchain_ollama import OllamaEmbeddings
        return OllamaEmbeddings(
            model=os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        )

    if embedding_provider == "openai":
        # Used in production or when LLM_PROVIDER=anthropic.
        # Also usable standalone with LLM_PROVIDER=groq if you have an OpenAI key.
        from langchain_openai import OpenAIEmbeddings
        return OpenAIEmbeddings(
            model="text-embedding-3-large",
            api_key=os.getenv("OPENAI_API_KEY"),
        )

    raise ValueError(
        f"Unknown EMBEDDING_PROVIDER: {embedding_provider!r} — use 'ollama' or 'openai'"
    )