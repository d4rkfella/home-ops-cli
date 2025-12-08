import typer

from .download import app as download_app

app = typer.Typer()

app.add_typer(download_app)
