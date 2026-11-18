from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "IaC Security Scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8001
    API_PREFIX: str = ""

    # Database - MySQL
    DATABASE_URL: str = "mysql+pymysql://root:root@localhost:3306/iac_scanner"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:3001"]

    # Auth
    SAST_API_TOKEN: str = "changeme-token"

    # Scan configuration
    SCAN_TIMEOUT: int = 300
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_SCAN_FILES: int = 1000

    # Policy directory
    POLICY_DIRECTORY: str = str(Path(__file__).parent.parent.parent / "policies")

    # Report directory
    REPORT_DIRECTORY: str = str(Path(__file__).parent.parent.parent / "reports")

    # File extensions
    TERRAFORM_EXTENSIONS: list[str] = [".tf", ".tfvars", ".tf.json"]
    KUBERNETES_EXTENSIONS: list[str] = [".yaml", ".yml"]
    DOCKER_FILES: list[str] = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]
    CLOUDFORMATION_EXTENSIONS: list[str] = [".yaml", ".yml", ".json"]

    # Git configuration
    GIT_ALLOWED_HOSTS: list[str] = [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
    ]
    GIT_CLONE_TIMEOUT: int = 300
    GIT_MAX_REPO_SIZE: int = 500 * 1024 * 1024  # 500MB

    # ZIP upload configuration
    ZIP_MAX_SIZE: int = 250 * 1024 * 1024  # 250MB
    ZIP_MAX_EXTRACTED_SIZE: int = 1024 * 1024 * 1024  # 1GB
    ZIP_MAX_FILES: int = 10000

    # Security
    BLOCKED_PATHS: list[str] = [
        "/etc",
        "/var",
        "/usr",
        "/bin",
        "/sbin",
        "/root",
    ]
    MAX_INPUT_LENGTH: int = 2048

    # Engine flags
    INTERNAL_QUERIES_ENABLED: bool = True

    SCAN_MAX_FILES: int = 10000
    SCAN_MAX_FILE_SIZE_MB: int = 10
    MAX_CONCURRENT_SCANS: int = 4
    MAX_CONCURRENT_SCANNERS: int = 4
    AUTH_REQUIRED: bool = False
    LOG_LEVEL: str = "INFO"
    WORKSPACE_DIRECTORY: str = ""

    QUERY_DIRECTORY: str = str(Path(__file__).parent.parent / "queries_pack")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


import tempfile
Settings.model_rebuild()


@lru_cache()
def get_settings() -> Settings:
    return Settings()
