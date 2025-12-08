import typer

from .bootstrap import app as bootstrap
from .raft_snapshot_restore import app as raft_snapshot_restore
from .pki import app as pki

app = typer.Typer()

app.add_typer(bootstrap)
app.add_typer(raft_snapshot_restore)
app.add_typer(pki, name="pki")
