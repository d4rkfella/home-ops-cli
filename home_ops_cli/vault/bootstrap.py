import re

import hvac
from hvac.exceptions import InvalidRequest
import typer
import time
from typing_extensions import Annotated

from ..utils import parse_regex
from .restore_raft_snapshot import restore_raft_snapshot

app = typer.Typer()


@app.command(
    help="Init, unseal and force restore a hashicorp vault cluster from S3 storage using raft snapshots"
)
def bootstrap(
    addr: Annotated[
        str,
        typer.Option(help="Vault address (or set VAULT_ADDR)", envvar="VAULT_ADDR"),
    ],
    s3_bucket: Annotated[
        str, typer.Option(help="S3 bucket where snapshots are stored")
    ],
    s3_prefix: Annotated[str, typer.Option(help="S3 prefix/folder for snapshots")] = "",
    filename: Annotated[
        str | None, typer.Option(help="Specific snapshot file to restore")
    ] = None,
    filename_regex: Annotated[
        re.Pattern | None,
        typer.Option(parser=parse_regex, help="Regex to match snapshot filenames"),
    ] = None,
    aws_profile: Annotated[str | None, typer.Option(help="AWS profile to use")] = None,
):
    client = hvac.Client(url=addr)

    if not client.sys.is_initialized():
        typer.echo("Vault is not initialized. Starting initialization sequence...")

        is_kms = False
        try:
            typer.echo("Attempting Auto-Unseal (KMS) initialization...")
            result = client.sys.initialize(recovery_shares=5, recovery_threshold=3)
            is_kms = True
            typer.echo("Successfully initialized with Auto-Unseal.")
        except InvalidRequest as e:
            if (
                "not applicable to seal type" in str(e).lower()
                or "secret_shares" in str(e).lower()
            ):
                typer.echo(
                    "KMS not supported by this instance. Falling back to Shamir initialization..."
                )
                result = client.sys.initialize(secret_shares=5, secret_threshold=3)
                is_kms = False
            else:
                raise e

        root_token = result["root_token"]
        client.token = root_token

        if not is_kms:
            typer.echo("Unsealing with Shamir keys...")
            keys = result["keys"]
            client.sys.submit_unseal_keys(keys)
        else:
            typer.echo("Waiting for Auto-Unseal to complete...")
            attempts = 0
            while client.sys.is_sealed() and attempts < 10:
                time.sleep(1)
                attempts += 1

            if client.sys.is_sealed():
                typer.echo(
                    "Error: Vault is still sealed after Auto-Unseal init. Check Vault logs."
                )
                raise typer.Exit(code=1)

        typer.echo("Vault is unsealed and ready. Starting restore...")

        restore_raft_snapshot(
            addr=addr,
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            filename=filename,
            filename_regex=filename_regex,
            aws_profile=aws_profile,
            force_restore=True,
            token=root_token,
        )
    else:
        typer.echo("Vault already initialized. Skipping bootstrap procedure.")
