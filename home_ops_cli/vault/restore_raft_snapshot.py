import re
from collections.abc import Mapping, Sequence
from typing import cast
from datetime import datetime
from dateutil.parser import parse as parse_datetime
import boto3
import botocore.exceptions
import hvac
import typer
from hvac.api.system_backend import Raft
from hvac.exceptions import InvalidRequest, VaultError
from typing_extensions import Annotated

from ..utils import parse_regex

app = typer.Typer()


def select_snapshot(
    contents: Sequence[Mapping[str, object]], filename_regex: re.Pattern | None
) -> str:
    if filename_regex:
        valid_objects: list[Mapping[str, object]] = []

        for o in contents:
            key = o.get("Key")
            if not isinstance(key, str):
                continue

            match = filename_regex.match(key)
            if not match:
                continue

            ts_str = match.group(1)
            try:
                ts = parse_datetime(ts_str)
                valid_objects.append({"Key": key, "Timestamp": ts})
            except ValueError:
                continue

        if not valid_objects:
            raise ValueError(
                "No valid snapshots found matching the filename regex with parseable timestamp"
            )

        latest_obj = max(valid_objects, key=lambda o: cast(datetime, o["Timestamp"]))
        return cast(str, latest_obj["Key"])

    else:
        valid_objects: list[Mapping[str, object]] = [
            o
            for o in contents
            if isinstance(o.get("Key"), str)
            and isinstance(o.get("LastModified"), datetime)
        ]
        if not valid_objects:
            raise RuntimeError("No valid snapshots with LastModified found")

        latest_obj = max(valid_objects, key=lambda o: cast(datetime, o["LastModified"]))
        return cast(str, latest_obj["Key"])


@app.command(help="Restore a HashiCorp Vault cluster from an S3 Raft snapshot.")
def restore_raft_snapshot(
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
    force_restore: Annotated[
        bool, typer.Option(help="Force restore snapshot, replacing existing data")
    ] = False,
    token: Annotated[
        str | None, typer.Option(help="Vault token to authenticate with")
    ] = None,
    username: Annotated[
        str | None, typer.Option(help="Vault username for authentication")
    ] = None,
    password: Annotated[
        str | None,
        typer.Option(help="Vault password for authentication", hide_input=True),
    ] = None,
):
    if filename and filename_regex:
        raise typer.BadParameter(
            "snapshot_file and filename_regex are mutually exclusive"
        )

    client = hvac.Client(url=addr)
    try:
        if token:
            client.token = token
        elif username and password:
            try:
                auth_resp = client.auth.userpass.login(
                    username=username, password=password
                )
                client.token = auth_resp["auth"]["client_token"]
            except InvalidRequest as e:
                safe_msg = str(e)
                typer.echo(
                    f"Vault authentication failed for user '{username}': {safe_msg}",
                    err=True,
                )
                raise typer.Exit(code=1)
            except VaultError as e:
                typer.echo(
                    f"Vault authentication failed for user '{username}': {e.__class__.__name__}",
                    err=True,
                )
                raise typer.Exit(code=1)
        else:
            raise typer.BadParameter(
                "You must provide either a Vault token or username/password to authenticate."
            )
    except Exception as e:
        typer.echo(f"Vault authentication unexpected error: {e}", err=True)
        raise typer.Exit(code=1)

    if not client.is_authenticated():
        typer.echo("Vault login failed!", err=True)
        raise typer.Exit(code=1)

    typer.echo("Vault authentication successful.")

    session = (
        boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
    )
    s3_client = session.client("s3")

    if filename:
        key = f"{s3_prefix}/{filename}" if s3_prefix else filename
        try:
            s3_client.head_object(Bucket=s3_bucket, Key=key)
        except botocore.exceptions.ClientError as e:
            error_info = e.response.get("Error", {})
            code = error_info.get("Code", "Unknown")
            msg = error_info.get("Message", "")
            typer.secho(
                f"Failed to access S3 object {key} in bucket {s3_bucket}: [{code}] {msg}",
                err=True,
            )
            raise typer.Exit(code=1)
        typer.echo(f"Selected user-provided snapshot: {key}")
    else:
        try:
            resp = s3_client.list_objects_v2(Bucket=s3_bucket, Prefix=s3_prefix)
        except botocore.exceptions.ClientError as e:
            error_info = e.response.get("Error", {})
            code = error_info.get("Code", "Unknown")
            msg = error_info.get("Message", "")
            typer.secho(
                f"Failed to list S3 objects in bucket {s3_bucket}: [{code}]: {msg}",
                err=True,
            )
            raise typer.Exit(code=1)

        contents = cast(Sequence[Mapping[str, object]], resp.get("Contents", []))
        if not contents:
            typer.secho(f"No snapshots found in s3://{s3_bucket}/{s3_prefix}")
            raise typer.Exit(code=0)

        key = select_snapshot(contents, filename_regex=filename_regex)
        typer.echo(f"Selected latest snapshot: {key}")

        try:
            if not (
                snapshot_bytes := s3_client.get_object(Bucket=s3_bucket, Key=key)[
                    "Body"
                ].read()
            ):
                typer.secho(f"Snapshot {key} is empty or invalid.")
                raise typer.Exit(code=1)

            typer.echo("Restoring snapshot via Raft API...")
            try:
                raft = Raft(client.adapter)
                if force_restore:
                    resp = raft.force_restore_raft_snapshot(snapshot_bytes)
                else:
                    resp = raft.restore_raft_snapshot(snapshot_bytes)

                if resp.status_code >= 400:
                    typer.echo(f"Vault restore failed: {resp.text}", err=True)
                    raise typer.Exit(code=1)

            except Exception as e:
                typer.secho(f"Vault restore failed unexpectedly: {e}", err=True)
                raise typer.Exit(code=1)

            typer.echo("Vault restore completed successfully.")

        except botocore.exceptions.ClientError as e:
            error_info = e.response.get("Error", {})
            code = error_info.get("Code", "Unknown")
            msg = error_info.get("Message", "")
            typer.secho(
                f"Failed to download snapshot {key} from bucket {s3_bucket}: [{code}] {msg}",
                err=True,
            )
            raise typer.Exit(code=1)
