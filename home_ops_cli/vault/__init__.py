import typer

from .bootstrap import app as bootstrap
from .pki import app as pki
from .raft_snapshot_restore import app as raft_snapshot_restore

app = typer.Typer()

app.add_typer(bootstrap)
app.add_typer(raft_snapshot_restore)
app.add_typer(pki, name="pki")
