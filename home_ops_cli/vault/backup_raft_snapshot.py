import datetime
import hashlib
import io
import os
import tarfile
from enum import Enum
from typing import Annotated

import boto3
import hvac
import typer
from click.core import ParameterSource
from requests import Response

from ..utils import handle_vault_authentication

app = typer.Typer()


class S3ChecksumAlgorithm(str, Enum):
    CRC32 = "CRC32"
    CRC32C = "CRC32C"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    CRC64NVME = "CRC64NVME"


def parse_sha256sums(content: bytes) -> dict[str, str]:
    sums = {}
    lines = content.strip().split(b"\n")
    for line in lines:
        trimmed_line = line.strip()
        if not trimmed_line:
            continue
        parts = trimmed_line.split()
        if len(parts) == 2:
            checksum = parts[0].decode("utf-8")
            filename = parts[1].decode("utf-8")
            sums[filename] = checksum
    return sums


def verify_internal_checksums(snapshot_data: bytes):
    typer.echo("Starting snapshot checksum verification...")
    snapshot_stream = io.BytesIO(snapshot_data)

    try:
        with tarfile.open(fileobj=snapshot_stream, mode="r:gz") as tar:
            sha_sums_content = None
            files_in_tar: dict[str, bytes] = {}

            for member in tar.getmembers():
                if not member.isfile():
                    continue

                f = tar.extractfile(member)
                if f is None:
                    continue

                content = f.read()

                if member.name == "SHA256SUMS":
                    sha_sums_content = content

                files_in_tar[member.name] = content

            if sha_sums_content is None:
                raise ValueError(
                    "SHA256SUMS file not found in the Raft snapshot archive."
                )

            expected_sums = parse_sha256sums(sha_sums_content)

            for name, expected_sum in expected_sums.items():
                content = files_in_tar.get(name)

                if content is None:
                    raise ValueError(
                        f"File '{name}' listed in SHA256SUMS not found in archive."
                    )

                computed_sum = hashlib.sha256(content).hexdigest()

                if computed_sum != expected_sum:
                    raise ValueError(
                        f"Checksum mismatch for file '{name}'. Expected: {expected_sum}, Got: {computed_sum}"
                    )

            typer.secho(
                "Internal checksum verification successful.", fg=typer.colors.CYAN
            )

    except tarfile.TarError as e:
        raise tarfile.TarError(f"Error reading Raft snapshot archive: {e}")


# --- Main Command ---


@app.command(
    help="Executes a complete workflow for obtaining a HashiCorp Vault Raft snapshot from a cluster, verifying its integrity, and uploading it securely to S3 storage. Provides flexible authentication options for both HashiCorp Vault and S3 APIs."
)
def backup_raft_snapshot(
    ctx: typer.Context,
    s3_bucket_name: Annotated[
        str, typer.Option(envvar="S3_BUCKET_NAME", help="Target S3 bucket name.")
    ],
    vault_address: Annotated[
        str, typer.Option(envvar="VAULT_ADDR", help="Vault server address.")
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
    vault_token: Annotated[
        str | None,
        typer.Option(envvar="VAULT_TOKEN", help="Vault authentication token."),
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
        typer.Option(help="The S3 key prefix (folder) to store the snapshot in."),
    ] = "",
    s3_checksum_algorithm: Annotated[
        S3ChecksumAlgorithm,
        typer.Option(help="The algorithm to use for s3 transport checksum."),
    ] = S3ChecksumAlgorithm.CRC64NVME,
):
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

    try:
        typer.echo("Requesting Vault Raft snapshot...")
        response: Response = vault_client.sys.take_raft_snapshot()

        if response.status_code != 200:
            typer.secho(
                f"Vault raft snapshot request failed with status code {response.status_code}.",
                fg=typer.colors.RED,
                bold=True,
            )
            typer.echo(f"Response body: {response.text}")
            raise typer.Exit(code=1)

        snapshot_data: bytes = response.content

        typer.echo("Vault Raft snapshot successfully retrieved.")

        verify_internal_checksums(snapshot_data)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        s3_key = f"{s3_key_prefix}vault-snapshot-{timestamp}.snap"

        typer.echo(
            f"Uploading snapshot to bucket '{s3_bucket_name}' with key '{s3_key}'..."
        )

        try:
            s3_client.upload_fileobj(
                io.BytesIO(snapshot_data),
                s3_bucket_name,
                s3_key,
                ExtraArgs={
                    "ContentType": "application/gzip",
                    "ChecksumAlgorithm": s3_checksum_algorithm,
                },
            )
        except Exception as e:
            raise Exception(f"Failed uploading Raft snapshot: {e}")

        typer.secho(
            "Raft snapshot sucessfully uploaded!", fg=typer.colors.GREEN, bold=True
        )

    except Exception as e:
        typer.secho(
            f"An error occurred during backup: {e}",
            fg=typer.colors.RED,
            bold=True,
        )
        raise typer.Exit(code=1)
