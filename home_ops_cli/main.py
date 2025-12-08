import typer

from .aws import app as aws
from .github import app as github
from .kubernetes import app as kubernetes
from .kubevirt import app as kubevirt
from .talos import app as talos
from .vault import app as vault
from .version import app as version

app = typer.Typer()

app.add_typer(version)
app.add_typer(kubevirt, name="kubevirt")
app.add_typer(github, name="github")
app.add_typer(talos, name="talos")
app.add_typer(vault, name="vault")
app.add_typer(aws, name="aws")
app.add_typer(kubernetes, name="kubernetes")


if __name__ == "__main__":
    app()
