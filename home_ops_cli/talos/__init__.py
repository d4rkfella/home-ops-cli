import typer

from .regen_talosconfig import app as regen_talosconfig

app = typer.Typer()

app.add_typer(regen_talosconfig)
