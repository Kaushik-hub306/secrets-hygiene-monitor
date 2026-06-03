"""Entry point for the API server."""

import os
import uvicorn
from dotenv import load_dotenv

load_dotenv()

host = os.getenv("HOST", "127.0.0.1")
port = int(os.getenv("PORT", "8000"))
reload = os.getenv("APP_ENV", "development") == "development"

if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )