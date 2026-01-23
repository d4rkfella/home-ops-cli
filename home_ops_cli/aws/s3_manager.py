from __future__ import annotations

import typer

app = typer.Typer()


@app.command()
def manager():
    from .textual_app import S3Browser

    S3Browser().run()
