import re
from datetime import datetime
from dateutil.parser import parse as parse_datetime
from collections.abc import Mapping, Sequence
from typing import cast

import typer
import boto3
import botocore.exceptions
import hvac
from hvac.api.system_backend import Raft
from typing_extensions import Annotated

app = typer.Typer()


def parse_regex(value: str) -> re.Pattern:
    try:
        pattern = re.compile(value)
    except re.error as e:
        raise typer.BadParameter(f"{e}")
    return pattern


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
    dry_run: Annotated[
        bool, typer.Option(help="If set, only selects snapshot without restoring")
    ] = False,
):
    if filename and filename_regex:
        raise typer.BadParameter(
            "snapshot_file and filename_regex are mutually exclusive"
        )

    session = (
        boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
    )
    s3_client = session.client("s3")

    try:
        if filename:
            key = f"{s3_prefix}/{filename}" if s3_prefix else filename
            try:
                s3_client.head_object(Bucket=s3_bucket, Key=key)
            except botocore.exceptions.ClientError as e:
                raise RuntimeError(
                    f"Snapshot {key} does not exist in bucket {s3_bucket}: {e}"
                )
            typer.echo(f"Selected user-provided snapshot: {key}")
        else:
            try:
                resp = s3_client.list_objects_v2(Bucket=s3_bucket, Prefix=s3_prefix)
            except botocore.exceptions.ClientError as e:
                raise RuntimeError(f"Failed to access bucket {s3_bucket}: {e}")

            if not (
                contents := cast(
                    Sequence[Mapping[str, object]], resp.get("Contents", [])
                )
            ):
                raise RuntimeError(
                    f"No snapshots found in s3://{s3_bucket}/{s3_prefix}"
                )

            key = select_snapshot(contents, filename_regex=filename_regex)
            typer.echo(f"Selected latest snapshot: {key}")

        typer.echo(f"Downloading snapshot from s3://{s3_bucket}/{key}")
        if not (
            snapshot_bytes := s3_client.get_object(Bucket=s3_bucket, Key=key)[
                "Body"
            ].read()
        ):
            raise RuntimeError(f"Snapshot {key} is empty or invalid.")

    except ValueError as ve:
        typer.echo(f"Snapshot selection failed: {ve}", err=True)
        raise typer.Exit(code=1)
    except RuntimeError as re_err:
        typer.echo(f"Error: {re_err}", err=True)
        raise typer.Exit(code=1)

    if dry_run:
        typer.echo("Dry-run mode: skipping Vault restore.")
        return

    client = hvac.Client(url=addr)
    raft = Raft(client.adapter)

    if not client.sys.is_initialized():
        typer.echo("Initializing Vault cluster...")
        result = client.sys.initialize()
        root_token = result["root_token"]
        keys = result["keys"]

        client.token = root_token
        typer.echo("Unsealing Vault cluster...")
        client.sys.submit_unseal_keys(keys)

        typer.echo("Restoring snapshot via Raft API...")
        resp = raft.force_restore_raft_snapshot(snapshot_bytes)
        if resp.status_code >= 400:
            typer.echo(f"Vault restore failed: {resp.text}", err=True)
            raise typer.Exit(code=1)
        typer.echo("Vault restore completed successfully.")
    else:
        typer.echo("Vault already initialized. Skipping bootstrap procedure.")
