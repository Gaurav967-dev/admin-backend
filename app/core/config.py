import os
from dotenv import load_dotenv

load_dotenv()

FRONTEND_ORIGIN = os.getenv(
    "FRONTEND_ORIGIN",
    "http://localhost:3000"
)

COOKIE_SECURE = (
    os.getenv("COOKIE_SECURE", "false").lower()
    == "true"
)