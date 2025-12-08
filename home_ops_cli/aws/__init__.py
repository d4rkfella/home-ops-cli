import typer

from .fetch_aws_ips import app as fetch_aws_ips_app
from .s3_manager import app as s3_manager_app

app = typer.Typer()

app.add_typer(fetch_aws_ips_app)
app.add_typer(s3_manager_app)
