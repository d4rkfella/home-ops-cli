import typer

from .regen_talosconfig import app as regen_talosconfig_app

app = typer.Typer()

app.add_typer(regen_talosconfig_app)
