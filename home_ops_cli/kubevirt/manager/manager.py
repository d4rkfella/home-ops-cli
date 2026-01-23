import typer

app = typer.Typer()


@app.command()
def manager():
    from .textual_app import KubevirtManager

    app = KubevirtManager()
    app.run()
