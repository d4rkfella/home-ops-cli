from typing import Any

import hvac
import typer
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from hvac.exceptions import InvalidPath, InvalidRequest, VaultError
from requests import Response
from typing_extensions import Annotated

app = typer.Typer()


def to_dict(resp: dict[str, Any] | Response | None) -> dict[str, Any]:
    if isinstance(resp, Response):
        return resp.json()
    if resp is None:
        return {}
    return resp


@app.command()
def rotate_issuing(
    vault_addr: Annotated[
        str | None,
        typer.Option(
            "--vault-addr",
            "-a",
            envvar="VAULT_ADDR",
            help="Vault URL (e.g., https://vault.example.com:8200)",
            prompt=True,
        ),
    ] = None,
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            "-t",
            envvar="VAULT_TOKEN",
            help="Vault token. If omitted, username/password login will be used.",
            prompt=True,
            prompt_required=False,
        ),
    ] = None,
):
    ISS_MOUNT = "pki_iss"
    INT_MOUNT = "pki_int"
    COMMON_NAME = "DarkfellaNET Issuing CA v1.1.1"
    TTL = "8760h"

    client = hvac.Client(url=vault_addr)

    if token:
        client.token = token
    else:
        typer.echo("Vault token not found, logging in with username/password.")
        username = typer.prompt("Vault username")
        password = typer.prompt("Vault password", hide_input=True)
        try:
            login_resp = client.auth.userpass.login(
                username=username, password=password
            )
            client.token = login_resp["auth"]["client_token"]
            typer.echo("Logged in successfully.")
        except InvalidRequest as e:
            typer.echo(f"Vault login failed: {e}")
            raise typer.Exit(1)

    if not client.is_authenticated():
        typer.echo("Authentication to Vault failed.")
        raise typer.Exit(1)

    typer.echo(f"Connected to Vault at {vault_addr}")

    try:
        typer.echo("Generating CSR using existing key material...")
        generate_resp = to_dict(
            client.write(
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
        typer.echo(f"Failed to generate CSR: {e}")
        raise typer.Exit(1)

    try:
        typer.echo("Signing CSR with intermediate CA...")
        sign_resp = to_dict(
            client.write(
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
        typer.echo(f"Failed to sign CSR: {e}")
        raise typer.Exit(1)

    try:
        typer.echo(f"Importing signed certificate back into {ISS_MOUNT}...")
        import_resp = to_dict(
            client.write(
                f"{ISS_MOUNT}/intermediate/set-signed",
                certificate=signed_cert,
                wrap_ttl=None,
            )
        )
        imported_issuers = import_resp.get("data", {}).get("imported_issuers", [])
        if not imported_issuers:
            raise RuntimeError("Vault did not return an imported issuer ID!")
        new_issuer_id = imported_issuers[0]

        client.write(
            f"{ISS_MOUNT}/config/issuers", default=new_issuer_id, wrap_ttl=None
        )
        typer.echo(f"New issuer {new_issuer_id} set as default")
    except (VaultError, InvalidRequest, InvalidPath) as e:
        typer.echo(f"Failed to import signed certificate: {e}")
        raise typer.Exit(1)

    cert = x509.load_pem_x509_certificate(signed_cert.encode(), default_backend())
    typer.echo("\nNew Issuing CA info:")
    typer.echo(f"  Subject: {cert.subject.rfc4514_string()}")
    typer.echo(f"  Serial: {cert.serial_number}")
    typer.echo(f"  Expires: {cert.not_valid_after.isoformat()} UTC")

    typer.echo("Done! Issuing CA successfully reissued and set as default.")
