import typer

from .ensure_namespace import app as ensure_namespace_app
from .wait import app as wait_app
from .apply import app as apply_app
from .apply_crds import app as apply_crds_app

app = typer.Typer()

app.add_typer(ensure_namespace_app)
app.add_typer(wait_app)
app.add_typer(apply_app)
app.add_typer(apply_crds_app)
