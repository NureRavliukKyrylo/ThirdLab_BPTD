from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from web.routes import router as web_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Lab 3 – Hash Function Web Interface",
        description="Web interface for computing custom 2/4/8-bit hash digests",
        version="1.0.0",
    )

    templates = Jinja2Templates(directory="web/templates")
    app.state.templates = templates

    app.mount("/static", StaticFiles(directory="web/static"), name="static")

    app.include_router(web_router)

    return app


app = create_app()
