from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import cast

import typer
from dateutil.parser import parse as parse_datetime

from ..options import (
    AwsAccessKeyIdOption,
    AwsEndpointUrlOption,
    AwsProfileOption,
    AwsRegionOption,
    AwsSecretAccessKeyOption,
    S3BucketNameOption,
    S3KeyPrefixOption,
    VaultAddressOption,
    VaultCACertOption,
    VaultCAPathOption,
    VaultK8sMountPointOption,
    VaultK8sRoleOption,
    VaultSkipVerifyOption,
    VaultSnapshotForceRestoreOption,
    VaultSnapshotNameOption,
    VaultSnapshotNameRegexOption,
    VaultTokenOption,
)

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
    vault_address: VaultAddressOption,
    s3_bucket_name: S3BucketNameOption,
    vault_k8s_role: VaultK8sRoleOption = None,
    vault_k8s_mount_point: VaultK8sMountPointOption = "kubernetes",
    filename: VaultSnapshotNameOption = None,
    filename_regex: VaultSnapshotNameRegexOption = None,
    aws_profile: AwsProfileOption = None,
    aws_access_key_id: AwsAccessKeyIdOption = None,
    aws_secret_access_key: AwsSecretAccessKeyOption = None,
    aws_endpoint_url: AwsEndpointUrlOption = None,
    aws_region: AwsRegionOption = "us-east-1",
    s3_key_prefix: S3KeyPrefixOption = "",
    force_restore: VaultSnapshotForceRestoreOption = False,
    vault_token: VaultTokenOption = None,
    vault_ca_cert: VaultCACertOption = None,
    vault_ca_path: VaultCAPathOption = None,
    vault_skip_verify: VaultSkipVerifyOption = False,
):
    import botocore.exceptions
    import hvac
    from click.core import ParameterSource
    from hvac.api.system_backend import Raft

    from ..utils import create_s3_client, handle_vault_authentication

    if filename and filename_regex:
        raise typer.BadParameter("filename and filename-regex are mutually exclusive")

    if (
        vault_address
        and ctx.get_parameter_source("vault_address") == ParameterSource.COMMANDLINE
    ):
        os.environ["VAULT_ADDR"] = vault_address

    if (
        vault_token
        and ctx.get_parameter_source("vault_token") == ParameterSource.COMMANDLINE
    ):
        os.environ["VAULT_TOKEN"] = vault_token

    if (
        aws_profile
        and ctx.get_parameter_source("aws_profile") == ParameterSource.COMMANDLINE
    ):
        os.environ["AWS_PROFILE"] = aws_profile

    if (
        aws_endpoint_url
        and ctx.get_parameter_source("aws_endpoint_url") == ParameterSource.COMMANDLINE
    ):
        os.environ["AWS_ENDPOINT_URL"] = aws_endpoint_url

    if (
        aws_access_key_id
        and aws_secret_access_key
        and ctx.get_parameter_source("aws_access_key_id") == ParameterSource.COMMANDLINE
        and ctx.get_parameter_source("aws_secret_access_key")
        == ParameterSource.COMMANDLINE
    ):
        os.environ["AWS_ACCESS_KEY_ID"] = aws_access_key_id
        os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret_access_key

    if ctx.get_parameter_source("aws_region") == ParameterSource.COMMANDLINE:
        os.environ["AWS_REGION"] = aws_region

    vault_client = handle_vault_authentication(
        hvac.Client(
            verify=(
                str(vault_ca_cert)
                if vault_ca_cert
                else str(vault_ca_path)
                if vault_ca_path
                else (not vault_skip_verify)
            )
        ),
        vault_token=vault_token,
        k8s_role=vault_k8s_role,
        k8s_mount_point=vault_k8s_mount_point,
    )
    if vault_client.sys.is_sealed():
        typer.secho("Vault is sealed. Cannot proceed..", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    typer.echo("Initializing S3 client...")
    s3_client = create_s3_client(bucket_name=s3_bucket_name)
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
