"""
Centralised configuration using pydantic-settings.
All services import Settings from here — reads from environment / .env file.

Usage:
    from appsec_shared.config import settings
    print(settings.kafka_brokers)
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    kafka_brokers: str = "localhost:9092"

    postgres_url: str = "postgresql://appsec:appsec@postgres:5432/appsec"
    qdrant_url: str = "http://localhost:6333"
    redis_url: str = "redis://localhost:6379"

    aws_access_key_id: str = "minioadmin"
    aws_secret_access_key: str = "minioadmin"
    aws_endpoint_url: str = "http://localhost:9000"
    aws_default_region: str = "us-east-1"
    s3_force_path_style: bool = True

    llm_provider: str = "ollama"
    ollama_model: str = "qwen2.5-coder:7b-instruct-q4_K_M"
    ollama_embed_model: str = "nomic-embed-text"
    ollama_base_url: str = "http://localhost:11434"
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5-20251001"
    openai_api_key: str = ""

    github_token: str = ""

    flink_checkpoint_dir: str = "s3://flink-checkpoints/appsec"
    flink_parallelism: int = 2

    mcp_server_port: int = 8000


settings = Settings()
