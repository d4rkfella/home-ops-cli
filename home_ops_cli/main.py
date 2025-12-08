import typer

from .kubevirt import app as kubevirt_app
from .gh import app as github_app
from .version import app as version_app
from .talos import app as talos_app
from .vault import app as vault_app
from .aws import app as aws_app

app = typer.Typer()

app.add_typer(version_app)
app.add_typer(kubevirt_app, name="kubevirt")
app.add_typer(github_app, name="gh")
app.add_typer(talos_app, name="talos")
app.add_typer(vault_app, name="vault")
app.add_typer(aws_app, name="aws")


if __name__ == "__main__":
    app()
