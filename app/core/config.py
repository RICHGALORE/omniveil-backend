from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    app_name: str = "Omni Veil Trust OS"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    frontend_url: str = "http://localhost:3001"
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/omniveil"
    redis_url: str = "redis://localhost:6379/0"
    omni_api_key: str = "ov_live_your_key_here"
    upload_dir: str = "uploads"
    watermark_dir: str = "watermarked"
    max_upload_mb: int = 50

    # External synthetic-media providers. HIVE_API_KEY is retained as a legacy
    # fallback for Hive visual-media detection only. Audio and music use their
    # own project/model keys so provider evidence cannot be silently mislabeled.
    hive_api_key: str = ""
    hive_media_api_key: str = ""
    hive_audio_api_key: str = ""
    hive_music_api_key: str = ""
    sightengine_user: str = ""
    sightengine_secret: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
