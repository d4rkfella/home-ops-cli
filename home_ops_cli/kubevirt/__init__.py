import typer

from .manager import app as manager
from .vmexport import app as vmexport

app = typer.Typer()

app.add_typer(vmexport, name="vmexport")
app.add_typer(manager)
