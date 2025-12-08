import typer

from .manager import app as manager_app

app = typer.Typer()

app.add_typer(manager_app)
