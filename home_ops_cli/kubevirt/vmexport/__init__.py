import typer

from .download import app as download

app = typer.Typer()

app.add_typer(download)
