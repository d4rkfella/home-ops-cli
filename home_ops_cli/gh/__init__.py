import typer

from .delete_workflow_runs import app as delete_workflows_app

app = typer.Typer()

app.add_typer(delete_workflows_app)
