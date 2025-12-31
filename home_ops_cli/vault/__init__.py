import typer

from .backup_raft_snapshot import app as backup_raft_snapshot
from .bootstrap import app as bootstrap
from .login import app as login
from .pki import app as pki
from .restore_raft_snapshot import app as restore_raft_snapshot

app = typer.Typer()

app.add_typer(bootstrap)
app.add_typer(restore_raft_snapshot)
app.add_typer(backup_raft_snapshot)
app.add_typer(login)
app.add_typer(pki, name="pki")
