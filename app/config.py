"""Application configuration from environment variables."""

import os

WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
WEB_SECRET_KEY = os.getenv("WEB_SECRET_KEY", "dev-secret-change-in-production")
JWT_SECRET = os.getenv("JWT_SECRET", os.getenv("AICC_JWT_SECRET", "dev-jwt-secret"))
DB_PATH = os.getenv("DB_PATH", "data/aicc.db")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

# OAuth constants
ISSUER = "https://theintentlayer.com"
MCP_RESOURCE = "https://mcp.theintentlayer.com/mcp"
AUTH_CODE_LIFETIME_SECONDS = 600  # 10 minutes
ACCESS_TOKEN_LIFETIME_SECONDS = 3600  # 1 hour
REFRESH_TOKEN_LIFETIME_DAYS = 30
SUPPORTED_SCOPES = ["mcp:tools", "mcp:resources"]
