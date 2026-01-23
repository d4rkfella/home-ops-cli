import os
from typing import Any

from requests import Response
from typer import Context, Exit, Typer, colors, echo, secho

from ...options import (
    VaultAddressOption,
    VaultCACertOption,
    VaultCAPathOption,
    VaultSkipVerifyOption,
    VaultTokenOption,
)

app = Typer()


def to_dict(resp: dict[str, Any] | Response | None) -> dict[str, Any]:
    if isinstance(resp, Response):
        return resp.json()
    if resp is None:
        return {}
    return resp


@app.command()
def rotate_issuing(
    ctx: Context,
    vault_address: VaultAddressOption,
    vault_token: VaultTokenOption = None,
    vault_ca_cert: VaultCACertOption = None,
    vault_ca_path: VaultCAPathOption = None,
    vault_skip_verify: VaultSkipVerifyOption = False,
):
    ISS_MOUNT = "pki_iss"
    INT_MOUNT = "pki_int"
    COMMON_NAME = "DarkfellaNET Issuing CA v1.1.1"
    TTL = "8760h"

    from click.core import ParameterSource

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

    import hvac
    from hvac.exceptions import InvalidPath, InvalidRequest, VaultError

    from ...utils import handle_vault_authentication

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
    )

    if vault_client.sys.is_sealed():
        secho("Vault is sealed. Cannot proceed..", fg=colors.RED, bold=True)
        raise Exit(code=1)

    try:
        echo("Generating CSR using existing key material...")
        generate_resp = to_dict(
            vault_client.write(
                f"{ISS_MOUNT}/issuers/generate/intermediate/existing",
                common_name=COMMON_NAME,
                country="Bulgaria",
                locality="Sofia",
                organization="DarkfellaNET",
                ttl=TTL,
                format="pem_bundle",
                wrap_ttl=None,
            )
        )
        csr = generate_resp["data"]["csr"]
    except (VaultError, InvalidRequest) as e:
        echo(f"Failed to generate CSR: {e}")
        raise Exit(1)

    try:
        echo("Signing CSR with intermediate CA...")
        sign_resp = to_dict(
            vault_client.write(
                f"{INT_MOUNT}/root/sign-intermediate",
                csr=csr,
                country="Bulgaria",
                locality="Sofia",
                organization="DarkfellaNET",
                format="pem_bundle",
                ttl=TTL,
                common_name=COMMON_NAME,
                wrap_ttl=None,
            )
        )
        signed_cert = sign_resp["data"]["certificate"]
    except (VaultError, InvalidRequest) as e:
        echo(f"Failed to sign CSR: {e}")
        raise Exit(1)

    try:
        echo(f"Importing signed certificate back into {ISS_MOUNT}...")
        import_resp = to_dict(
            vault_client.write(
                f"{ISS_MOUNT}/intermediate/set-signed",
                certificate=signed_cert,
                wrap_ttl=None,
            )
        )
        imported_issuers = import_resp.get("data", {}).get("imported_issuers", [])
        if not imported_issuers:
            raise RuntimeError("Vault did not return an imported issuer ID!")
        new_issuer_id = imported_issuers[0]

        vault_client.write(
            f"{ISS_MOUNT}/config/issuers", default=new_issuer_id, wrap_ttl=None
        )
        echo(f"New issuer {new_issuer_id} set as default")
    except (VaultError, InvalidRequest, InvalidPath) as e:
        echo(f"Failed to import signed certificate: {e}")
        raise Exit(1)

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_pem_x509_certificate(signed_cert.encode(), default_backend())
    echo("\nNew Issuing CA info:")
    echo(f"  Subject: {cert.subject.rfc4514_string()}")
    echo(f"  Serial: {cert.serial_number}")
    echo(f"  Expires: {cert.not_valid_after.isoformat()} UTC")

    echo("Done! Issuing CA successfully reissued and set as default.")
