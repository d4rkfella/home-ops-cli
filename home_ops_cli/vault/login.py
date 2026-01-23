import os
from pathlib import Path
from typing import Annotated, Literal

import typer

from ..options import (
    VaultAddressOption,
    VaultCACertOption,
    VaultCAPathOption,
    VaultSkipVerifyOption,
)


def format_lease_duration(seconds: int) -> str:
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours}h{minutes}m{secs}s"


TOKEN_FILE = Path.home() / ".vault-token"

app = typer.Typer()


@app.command(help="Authenticate with Vault and optionally save the token.")
def login(
    ctx: typer.Context,
    vault_address: VaultAddressOption,
    vault_ca_cert: VaultCACertOption = None,
    vault_ca_path: VaultCAPathOption = None,
    vault_skip_verify: VaultSkipVerifyOption = False,
    method: Annotated[
        Literal["token", "userpass"],
        typer.Option(help="Auth method: token (default) or userpass"),
    ] = "token",
    no_store: Annotated[
        bool, typer.Option(help="Do not persist the token to disk", is_flag=True)
    ] = False,
    params: Annotated[
        list[str],
        typer.Argument(
            help="Auth parameters as key=value, like username=alice password=foo"
        ),
    ] = [],
):
    from click.core import ParameterSource

    if ctx.get_parameter_source("vault_address") == ParameterSource.COMMANDLINE:
        os.environ["VAULT_ADDR"] = vault_address

    kv = {}
    for p in params:
        if "=" not in p:
            raise typer.BadParameter(f"Invalid argument '{p}', expected key=value")
        k, v = p.split("=", 1)
        kv[k] = v

    import hvac

    client = hvac.Client(
        verify=(
            str(vault_ca_cert)
            if vault_ca_cert
            else str(vault_ca_path)
            if vault_ca_path
            else (not vault_skip_verify)
        )
    )

    try:
        if method == "token":
            token = kv.get("token")
            if not token:
                client.token = typer.prompt(
                    "Token (will be hidden)", hide_input=True, type=str
                )
            lookup = client.auth.token.lookup_self()
            token_info = lookup["data"]
            print(token_info)

        elif method == "userpass":
            username = kv.get("username")
            password = kv.get("password")
            if not username:
                raise typer.BadParameter("'username' must be specified")
            if not password:
                password = typer.prompt(
                    "Password (will be hidden)", hide_input=True, type=str
                )
            auth_resp = client.auth.userpass.login(username=username, password=password)
            token_info = auth_resp["auth"]

        token = token_info.get("client_token") or token_info.get("id")
        accessor = token_info["accessor"]
        ttl = token_info.get("lease_duration") or token_info.get("ttl")
        renewable = token_info.get("renewable", False)
        token_policies = token_info.get("token_policies", [])
        identity_policies = token_info.get("identity_policies", [])
        policies = token_info.get("policies", [])
        metadata = token_info.get("metadata") or token_info.get("meta")
        if not no_store:
            TOKEN_FILE.write_text(client.token)

        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table("Key", "Value")
        table.add_row("token", token)
        table.add_row("token_accessor", accessor)
        table.add_row("token_duration", format_lease_duration(ttl))
        table.add_row("token_renewable", str(renewable))
        table.add_row("token_policies", str(token_policies))
        table.add_row("identity_policies", str(identity_policies))
        table.add_row("policies", str(policies))
        table.add_row("token_meta_username", metadata.get("username", "n/a"))
        console.print(table)

    except Exception as e:
        typer.secho(f"Error authenticating: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
