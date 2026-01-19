import typer

from .download import app as download
from .test_image import app as test_image

app = typer.Typer()

app.add_typer(download)
app.add_typer(test_image)
