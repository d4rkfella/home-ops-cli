import os
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import cast

import boto3
import botocore.exceptions
import hvac
import typer
from click.core import ParameterSource
from dateutil.parser import parse as parse_datetime
from hvac.api.system_backend import Raft
from typing_extensions import Annotated

from ..utils import handle_vault_authentication, parse_regex

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
    ctx: typer.Context,
    vault_address: Annotated[
        str,
        typer.Option(help="Vault address (or set VAULT_ADDR)", envvar="VAULT_ADDR"),
    ],
    s3_bucket_name: Annotated[
        str,
        typer.Option(
            envvar="S3_BUCKET_NAME", help="S3 bucket where snapshots are stored"
        ),
    ],
    vault_k8s_role: Annotated[
        str | None, typer.Option(envvar="VAULT_K8S_ROLE", help="Vault K8s role name.")
    ] = None,
    vault_k8s_mount_point: Annotated[
        str,
        typer.Option(
            envvar="VAULT_K8S_MOUNT_POINT", help="K8s auth backend mount path."
        ),
    ] = "kubernetes",
    filename: Annotated[
        str | None, typer.Option(help="Specific snapshot file to restore")
    ] = None,
    filename_regex: Annotated[
        re.Pattern | None,
        typer.Option(parser=parse_regex, help="Regex to match snapshot filenames"),
    ] = None,
    aws_profile: Annotated[
        str | None,
        typer.Option(
            envvar="AWS_PROFILE", help="AWS Profile name to use for authentication."
        ),
    ] = None,
    aws_access_key_id: Annotated[
        str | None,
        typer.Option(envvar="AWS_ACCESS_KEY_ID", help="AWS Access Key ID."),
    ] = None,
    aws_secret_access_key: Annotated[
        str | None,
        typer.Option(
            envvar="AWS_SECRET_ACCESS_KEY",
            help="AWS Secret Access Key.",
        ),
    ] = None,
    aws_endpoint_url: Annotated[
        str | None,
        typer.Option(
            envvar="AWS_ENDPOINT_URL",
            help="Custom AWS endpoint URL (e.g., for MinIO or Cloudflare R2).",
        ),
    ] = None,
    aws_region: Annotated[
        str,
        typer.Option(
            envvar="AWS_REGION", help="Official AWS Region (e.g., us-east-1)."
        ),
    ] = "us-east-1",
    s3_key_prefix: Annotated[
        str,
        typer.Option(help="The S3 key prefix (folder) where the snapshot is stored."),
    ] = "",
    force_restore: Annotated[
        bool, typer.Option(help="Force restore snapshot, replacing existing data")
    ] = False,
    vault_token: Annotated[
        str | None, typer.Option(help="Vault token to authenticate with")
    ] = None,
    vault_ca_cert: Annotated[
        str | None,
        typer.Option(
            envvar="VAULT_CACERT",
            help="Path to Vault CA certificate.",
        ),
    ] = None,
    vault_ca_path: Annotated[
        str | None,
        typer.Option(
            envvar="VAULT_CAPATH",
            help="Path to directory of Vault CA certificates.",
        ),
    ] = None,
    vault_skip_verify: Annotated[
        bool,
        typer.Option(
            envvar="VAULT_SKIP_VERIFY", help="Skip Vault TLS certificate verification."
        ),
    ] = False,
):
    if filename and filename_regex:
        raise typer.BadParameter("filename and filename-regex are mutually exclusive")

    if ctx.get_parameter_source("aws_endpoint_url") == ParameterSource.COMMANDLINE:
        os.environ["AWS_ENDPOINT_URL"] = aws_endpoint_url

    if ctx.get_parameter_source("vault_address") == ParameterSource.COMMANDLINE:
        os.environ["VAULT_ADDR"] = vault_address

    if ctx.get_parameter_source("vault_token") == ParameterSource.COMMANDLINE:
        os.environ["VAULT_TOKEN"] = vault_token

    if ctx.get_parameter_source("aws_profile") == ParameterSource.COMMANDLINE:
        os.environ["AWS_PROFILE"] = aws_profile

    if (
        ctx.get_parameter_source("aws_access_key_id") == ParameterSource.COMMANDLINE
        and ctx.get_parameter_source("aws_secret_access_key")
        == ParameterSource.COMMANDLINE
    ):
        os.environ["AWS_ACCESS_KEY_ID"] = aws_access_key_id
        os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret_access_key

    if ctx.get_parameter_source("aws_region") == ParameterSource.COMMANDLINE:
        os.environ["AWS_REGION"] = aws_region

    vault_client = handle_vault_authentication(
        hvac.Client(verify=vault_ca_cert or vault_ca_path or not vault_skip_verify),
        vault_token=vault_token,
        k8s_role=vault_k8s_role,
        k8s_mount_point=vault_k8s_mount_point,
    )

    if vault_client.sys.is_sealed():
        typer.secho("Vault is sealed. Cannot proceed..", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    typer.echo("Initializing S3 client...")

    session = boto3.Session()
    s3_client = session.client("s3")
    typer.echo("S3 client initialized.")

    if filename:
        key = f"{s3_key_prefix}/{filename}" if s3_key_prefix else filename
        try:
            s3_client.head_object(Bucket=s3_bucket_name, Key=key)
        except botocore.exceptions.ClientError as e:
            error_info = e.response.get("Error", {})
            code = error_info.get("Code", "Unknown")
            msg = error_info.get("Message", "")
            typer.secho(
                f"Failed to access S3 object {key} in bucket {s3_bucket_name}: [{code}] {msg}",
                err=True,
            )
            raise typer.Exit(code=1)
        typer.echo(f"Selected user-provided snapshot: {key}")
    else:
        try:
            resp = s3_client.list_objects_v2(
                Bucket=s3_bucket_name, Prefix=s3_key_prefix
            )
        except botocore.exceptions.ClientError as e:
            error_info = e.response.get("Error", {})
            code = error_info.get("Code", "Unknown")
            msg = error_info.get("Message", "")
            typer.secho(
                f"Failed to list S3 objects in bucket {s3_bucket_name}: [{code}]: {msg}",
                err=True,
            )
            raise typer.Exit(code=1)

        contents = cast(Sequence[Mapping[str, object]], resp.get("Contents", []))
        if not contents:
            typer.secho(f"No snapshots found in s3://{s3_bucket_name}/{s3_key_prefix}")
            raise typer.Exit(code=0)

        key = select_snapshot(contents, filename_regex=filename_regex)
        typer.echo(f"Selected latest snapshot: {key}")

        try:
            if not (
                snapshot_bytes := s3_client.get_object(Bucket=s3_bucket_name, Key=key)[
                    "Body"
                ].read()
            ):
                typer.secho(f"Snapshot {key} is empty or invalid.")
                raise typer.Exit(code=1)

            typer.echo("Restoring snapshot via Raft API...")
            try:
                raft = Raft(vault_client.adapter)
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
                f"Failed to download snapshot {key} from bucket {s3_bucket_name}: [{code}] {msg}",
                err=True,
            )
            raise typer.Exit(code=1)
