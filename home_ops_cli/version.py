import typer

app = typer.Typer()


@app.command()
def version():
    print("home-ops-cli Version 0.4.2")
