import typer

app = typer.Typer()


@app.command()
def version():
    print("home-ops-cli version 0.4.47")
