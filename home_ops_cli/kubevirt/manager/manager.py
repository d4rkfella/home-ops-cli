import typer

from .textual_app import KubevirtManager

app = typer.Typer()


@app.command()
def manager():
    app = KubevirtManager()
    app.run()
