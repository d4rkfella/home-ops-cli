from pathlib import Path
import typer
from typing import Annotated
import hvac
from rich.table import Table
from rich.console import Console


def format_lease_duration(seconds: int) -> str:
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours}h{minutes}m{secs}s"


TOKEN_FILE = Path.home() / ".vault-token"

app = typer.Typer()


@app.command(help="Authenticate with Vault and optionally save the token.")
def login(
    addr: Annotated[
        str,
        typer.Option(help="Vault address (or set VAULT_ADDR)", envvar="VAULT_ADDR"),
    ],
    method: Annotated[
        str, typer.Option(help="Auth method: token (default) or userpass")
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
    kv = {}
    for p in params:
        if "=" not in p:
            raise typer.BadParameter(f"Invalid argument '{p}', expected key=value")
        k, v = p.split("=", 1)
        kv[k] = v

    client = hvac.Client(url=addr)

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

        else:
            raise typer.BadParameter(f"Unknown method '{method}'")

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
