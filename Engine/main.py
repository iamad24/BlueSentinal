from fastapi import FastAPI

app = FastAPI(
    title="BlueSentinel XDR",
    description="AI Detection Engineering and Threat Hunting Platform",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "project": "BlueSentinel XDR",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }