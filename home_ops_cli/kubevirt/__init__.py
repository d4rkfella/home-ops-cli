import typer

from .manager import app as manager_app
from .vmexport import app as vmexport_app

app = typer.Typer()

app.add_typer(vmexport_app, name="vmexport")
app.add_typer(manager_app)
