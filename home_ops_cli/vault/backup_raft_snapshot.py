import io
import datetime
import typer
import hashlib
import tarfile
import boto3
from enum import Enum
from typing import Annotated
import hvac
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
    bucket_name: Annotated[
        str, typer.Option(envvar="S3_BUCKET_NAME", help="Target S3 bucket name.")
    ],
    vault_url: Annotated[
        str, typer.Option(envvar="VAULT_ADDR", help="Vault server address.")
    ],
    k8s_role: Annotated[
        str | None, typer.Option(envvar="VAULT_K8S_ROLE", help="Vault K8s role name.")
    ] = None,
    k8s_mount_point: Annotated[
        str,
        typer.Option(
            envvar="VAULT_K8S_MOUNT_POINT", help="K8s auth backend mount path."
        ),
    ] = "kubernetes",
    vault_token: Annotated[
        str | None,
        typer.Option(envvar="VAULT_TOKEN", help="Vault authentication token."),
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
    s3_endpoint_url: Annotated[
        str | None,
        typer.Option(
            envvar="S3_ENDPOINT_URL",
            help="Custom S3 endpoint URL (e.g., for MinIO or Cloudflare R2).",
        ),
    ] = None,
    aws_region: Annotated[
        str,
        typer.Option(
            envvar="AWS_REGION", help="Official AWS Region (e.g., us-east-1)."
        ),
    ] = "us-east-1",
    key_prefix: Annotated[
        str,
        typer.Option(help="The S3 key prefix (folder) to store the snapshot in."),
    ] = "",
    s3_checksum_algorithm: Annotated[
        S3ChecksumAlgorithm,
        typer.Option(help="The algorithm to use for s3 transport checksum."),
    ] = S3ChecksumAlgorithm.CRC64NVME,
):
    if k8s_role and vault_token:
        typer.secho(
            "Warning: Both a K8s role and a Vault token were provided. Kubernetes authentication will be prioritized.",
            fg=typer.colors.YELLOW,
            bold=True,
        )

    vault_client = handle_vault_authentication(
        hvac.Client(),
        vault_url=vault_url,
        vault_token=vault_token,
        k8s_role=k8s_role,
        k8s_mount_point=k8s_mount_point,
    )

    if vault_client.sys.is_sealed():
        typer.secho("Vault is sealed. Cannot proceed..", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    typer.echo("Initializing S3 client...")

    session_kwargs = {}
    client_kwargs = {}

    if aws_access_key_id and aws_secret_access_key:
        session_kwargs["aws_access_key_id"] = aws_access_key_id
        session_kwargs["aws_secret_access_key"] = aws_secret_access_key
        if s3_endpoint_url:
            client_kwargs["endpoint_url"] = s3_endpoint_url

    elif aws_profile:
        typer.echo(f"Using AWS profile: {aws_profile}")
        session_kwargs["profile_name"] = aws_profile

    else:
        typer.echo(
            "Using Boto3's default credential chain (IAM Role, standard ENV VARs, or shared files)."
        )

    session = boto3.Session(**session_kwargs)
    s3_client = session.client("s3", region_name=aws_region, **client_kwargs)
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
        s3_key = f"{key_prefix}vault-snapshot-{timestamp}.snap"

        typer.echo(
            f"Uploading snapshot to bucket '{bucket_name}' with key '{s3_key}'..."
        )

        try:
            s3_client.upload_fileobj(
                io.BytesIO(snapshot_data),
                bucket_name,
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
