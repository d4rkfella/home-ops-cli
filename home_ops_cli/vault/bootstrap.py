import os
import time
from typing import Any

import typer

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
    VaultSkipVerifyOption,
    VaultSnapshotNameOption,
    VaultSnapshotNameRegexOption,
)

app = typer.Typer()


@app.command(
    help="Init, unseal and force restore a hashicorp vault cluster from S3 storage using raft snapshots"
)
def bootstrap(
    ctx: typer.Context,
    vault_address: VaultAddressOption,
    s3_bucket_name: S3BucketNameOption,
    vault_ca_cert: VaultCACertOption = None,
    vault_ca_path: VaultCAPathOption = None,
    vault_skip_verify: VaultSkipVerifyOption = False,
    s3_key_prefix: S3KeyPrefixOption = "",
    filename: VaultSnapshotNameOption = None,
    filename_regex: VaultSnapshotNameRegexOption = None,
    aws_profile: AwsProfileOption = None,
    aws_access_key_id: AwsAccessKeyIdOption = None,
    aws_secret_access_key: AwsSecretAccessKeyOption = None,
    aws_endpoint_url: AwsEndpointUrlOption = None,
    aws_region: AwsRegionOption = "us-east-1",
):
    import hvac
    from click.core import ParameterSource

    if ctx.get_parameter_source("vault_address") == ParameterSource.COMMANDLINE:
        os.environ["VAULT_ADDR"] = vault_address

    client = hvac.Client(
        verify=(
            str(vault_ca_cert)
            if vault_ca_cert
            else str(vault_ca_path)
            if vault_ca_path
            else (not vault_skip_verify)
        )
    )

    if not client.sys.is_initialized():
        typer.echo("Vault is not initialized. Starting bootstrap procedure...")
        seal_status: dict[str, Any] = client.sys.read_seal_status()
        seal_type = seal_status["type"]

        is_kms = seal_type != "shamir"

        if is_kms:
            typer.echo(
                f"Detected Auto-Unseal ({seal_type}). Initializing with recovery keys..."
            )
            result = client.sys.initialize(recovery_shares=5, recovery_threshold=3)
            typer.echo("Successfully initialized with Auto-Unseal.")
        else:
            typer.echo("Detected Shamir seal. Initializing with secret shares...")
            result = client.sys.initialize(secret_shares=5, secret_threshold=3)
            typer.echo("Successfully initialized with Shamir seal.")

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

        from .restore_raft_snapshot import restore_raft_snapshot

        restore_raft_snapshot(
            ctx=ctx,
            vault_address=vault_address,
            vault_ca_cert=vault_ca_cert,
            vault_ca_path=vault_ca_path,
            vault_skip_verify=vault_skip_verify,
            s3_bucket_name=s3_bucket_name,
            s3_key_prefix=s3_key_prefix,
            filename=filename,
            filename_regex=filename_regex,
            aws_profile=aws_profile,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_endpoint_url=aws_endpoint_url,
            aws_region=aws_region,
            force_restore=True,
            vault_token=root_token,
        )
    else:
        typer.echo("Vault already initialized. Skipping bootstrap procedure.")
