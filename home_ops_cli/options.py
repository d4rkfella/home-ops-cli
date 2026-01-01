import re
from pathlib import Path
from typing import Annotated

import typer

from .utils import parse_regex, validate_s3_key_prefix, validate_vault_address

AwsEndpointUrlOption = Annotated[
    str | None,
    typer.Option(
        envvar="AWS_ENDPOINT_URL",
        help="Custom AWS endpoint URL (e.g., for MinIO or Cloudflare R2).",
    ),
]

AwsAccessKeyIdOption = Annotated[
    str | None,
    typer.Option(envvar="AWS_ACCESS_KEY_ID", help="AWS Access Key ID."),
]

AwsSecretAccessKeyOption = Annotated[
    str | None,
    typer.Option(
        envvar="AWS_SECRET_ACCESS_KEY",
        help="AWS Secret Access Key.",
    ),
]

AwsProfileOption = Annotated[
    str | None,
    typer.Option(envvar="AWS_PROFILE", help="AWS CLI profile name to use."),
]

AwsRegionOption = Annotated[
    str,
    typer.Option(envvar="AWS_REGION", help="AWS Region (e.g., us-east-1)."),
]

S3BucketNameOption = Annotated[
    str,
    typer.Option(
        envvar="S3_BUCKET_NAME",
        help="S3 bucket where snapshots are stored",
    ),
]

S3KeyPrefixOption = Annotated[
    str,
    typer.Option(
        callback=validate_s3_key_prefix,
    ),
]

VaultAddressOption = Annotated[
    str,
    typer.Option(
        callback=validate_vault_address,
        default_factory=lambda: "https://127.0.0.1:8200",
        envvar="VAULT_ADDR",
        show_envvar=False,
        help="Address of the Vault server. The default is https://127.0.0.1:8200. This can also be specified via the VAULT_ADDR environment variable.",
    ),
]

VaultTokenOption = Annotated[
    str | None,
    typer.Option(
        envvar="VAULT_TOKEN",
        show_envvar=False,
        help=(
            "Vault token used to authenticate with the Vault server. "
            "This can also be specified via the VAULT_TOKEN environment variable."
        ),
    ),
]

VaultCACertOption = Annotated[
    Path | None,
    typer.Option(
        envvar="VAULT_CACERT",
        show_envvar=False,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        writable=False,
        resolve_path=True,
        path_type=str,
        help=(
            "Path on the local disk to a single PEM-encoded CA certificate to verify the Vault server's SSL certificate. "
            "This takes precedence over -ca-path. This can also be specified via the VAULT_CACERT environment variable."
        ),
    ),
]

VaultCAPathOption = Annotated[
    Path | None,
    typer.Option(
        envvar="VAULT_CAPATH",
        show_envvar=False,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        writable=False,
        resolve_path=True,
        path_type=str,
        help=(
            "Path on the local disk to a directory of PEM-encoded CA certificates to verify the Vault server's SSL certificate. "
            "This can also be specified via the VAULT_CAPATH environment variable."
        ),
    ),
]

VaultSkipVerifyOption = Annotated[
    bool,
    typer.Option(
        show_envvar=False,
        envvar="VAULT_SKIP_VERIFY",
        help=(
            "Disable verification of TLS certificates. Using this option is highly discouraged "
            "as it decreases the security of data transmissions to and from the Vault server. "
            "The default is false. This can also be specified via the VAULT_SKIP_VERIFY environment variable."
        ),
    ),
]

VaultK8sRoleOption = Annotated[
    str | None,
    typer.Option(envvar="VAULT_K8S_ROLE", help="Vault K8s role name."),
]

VaultK8sMountPointOption = Annotated[
    str,
    typer.Option(
        envvar="VAULT_K8S_MOUNT_POINT", help="Vault K8s auth backend mount path."
    ),
]

VaultSnapshotNameOption = Annotated[
    str | None,
    typer.Option(
        help="Name of the Vault snapshot to restore.",
    ),
]

VaultSnapshotNameRegexOption = Annotated[
    re.Pattern | None,
    typer.Option(
        parser=parse_regex,
        help="Regex pattern to match Vault snapshot names.",
    ),
]

VaultSnapshotForceRestoreOption = Annotated[
    bool,
    typer.Option(
        help=(
            "Force snapshot restore when the unseal keys or auto-unseal configuration "
            "are inconsistent with the snapshot, such as when restoring data from "
            "a different Vault cluster."
        ),
    ),
]
