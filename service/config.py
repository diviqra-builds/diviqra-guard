# MIT License — Copyright (c) 2026 Diviqra
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    GUARD_API_KEY: str = ""  # Set via environment variable
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/diviqra"
    REDIS_URL: str = "redis://localhost:7379/0"
    OLLAMA_URL: str = "http://localhost:11434"

    GUARD_HOST: str = "0.0.0.0"
    GUARD_PORT: int = 7008
    GUARD_WORKERS: int = 2

    CLASSIFIER_MODEL_PATH: str = "service/models/distilbert-guard.onnx"
    CLASSIFIER_ENABLED: bool = False

    LOG_LEVEL: str = "INFO"

    MAX_REQUESTS_PER_MINUTE: int = 60
    MAX_TOKENS_PER_REQUEST_INGRESS: int = 4000
    MAX_TOKENS_PER_REQUEST_EGRESS: int = 8000

    WALL2_TIMEOUT: float = 3.0
    WALL2_CACHE_TTL: int = 3600

    VERSION: str = "1.0.0"

    # JWT public key — shared with platform backend for Guard JWT verification
    GUARD_JWT_PUBLIC_KEY: str = ""

    # Razorpay
    RAZORPAY_KEY_ID: str = ""  # Set via environment variable
    RAZORPAY_KEY_SECRET: str = ""  # Set via environment variable
    RAZORPAY_WEBHOOK_SECRET: str = ""  # Set via environment variable

    # Stripe — USD billing for international customers
    STRIPE_SECRET_KEY: str = ""  # Set via environment variable
    STRIPE_PUBLISHABLE_KEY: str = ""  # Set via environment variable
    STRIPE_WEBHOOK_SECRET: str = ""  # Set via environment variable
    STRIPE_PRO_PRICE_ID: str = ""  # price_... from Stripe dashboard
    STRIPE_ENTERPRISE_PRICE_ID: str = ""  # price_... from Stripe dashboard

    # Transactional email (upgrade notifications)
    RESEND_API_KEY: str = ""  # Set via environment variable
    GUARD_FROM_EMAIL: str = "Diviqra Guard <guard@diviqra.com>"


settings = Settings()
