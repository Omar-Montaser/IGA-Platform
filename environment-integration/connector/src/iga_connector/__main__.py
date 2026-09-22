import os
import uvicorn
uvicorn.run("iga_connector.api:app",
            host=os.environ.get("IGA_HOST", "127.0.0.1"),
            port=int(os.environ.get("IGA_PORT", "8000")))
