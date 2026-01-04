import os

DATABASE_URL = os.getenv("DATABASE_URL")
NETWORK_ID = os.getenv("NETWORK_ID", "SETONLYCHAIN")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")
