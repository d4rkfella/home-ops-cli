import typer

from .delete_workflow_runs import app as delete_workflows

app = typer.Typer()

app.add_typer(delete_workflows)
