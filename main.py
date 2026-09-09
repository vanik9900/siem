from fastapi import FastAPI

app = FastAPI(
    title="siem",
    description="System Information And Event Management",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "project": "siem",
        "status": "running"
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok"
    }