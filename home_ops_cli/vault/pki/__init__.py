import typer

from .rotate_issuing import app as rotate_issuing_app

app = typer.Typer()

app.add_typer(rotate_issuing_app)
