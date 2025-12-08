import typer

from .wait import app as wait

app = typer.Typer()

app.add_typer(wait)
