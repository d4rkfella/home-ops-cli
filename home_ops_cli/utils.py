from __future__ import annotations

import asyncio
import random
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast, overload

if TYPE_CHECKING:
    import aiohttp
    import hvac
    from rich.console import Console
    from mypy_boto3_s3 import S3Client

import typer


def async_command(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


def find_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


async def retry_with_backoff(
    fn, *args, retries=5, base_delay=2, console: Console | None = None, **kwargs
):
    from .exceptions import RetryLimitExceeded

    attempt = 0
    while True:
        try:
            return await fn(*args, **kwargs)

        except (ConnectionError, OSError) as e:
            if attempt >= retries:
                raise RetryLimitExceeded(e, retries)

            delay = base_delay * (2**attempt) + random.uniform(0, 0.3)
            attempt += 1

            msg = f"retrying in {delay:.1f}s... ({attempt}/{retries})"

            if console:
                console.print(f"[bold red]{e}[/bold red]")
                console.print(f"[yellow]{msg}[/yellow]")
            else:
                print(f"{e}")
                print(msg)

            await asyncio.sleep(delay)


@asynccontextmanager
async def dynamic_client():
    from kubernetes_asyncio import client, config
    from kubernetes_asyncio.config import ConfigException
    from kubernetes_asyncio.dynamic import DynamicClient

    try:
        await config.load_kube_config()
        print("Configuration loaded from kubeconfig.")
    except ConfigException:
        try:
            config.load_incluster_config()
            print("Loaded in-cluster congig.")
        except ConfigException as e:
            raise RuntimeError(f"Could not load Kubernetes configuration: {e}")
    async with client.ApiClient() as api_client:
        dyn_client = await DynamicClient(api_client)
        yield dyn_client


def validate_kube_rfc1123_label(value: str | list[str]) -> str | list[str]:
    """Validate Kubernetes RFC1123 label format."""

    def validate_item(item: str) -> str:
        normalized = item.lower()

        if len(normalized) > 63:
            raise typer.BadParameter(
                f"Name '{normalized}' cannot be longer than 63 characters. "
                f"Found {len(normalized)}."
            )

        if not re.fullmatch(r"[a-z0-9-]+", normalized):
            raise typer.BadParameter(
                f"Name '{normalized}' must contain only lowercase alphanumeric "
                f"characters or hyphen ('-')."
            )

        if not normalized[0].isalpha():
            raise typer.BadParameter(
                f"Name '{normalized}' must start with an alphabetic character (a-z)."
            )

        if not normalized[-1].isalnum():
            raise typer.BadParameter(
                f"Name '{normalized}' must end with an alphanumeric character "
                f"(a-z or 0-9)."
            )

        return normalized

    if isinstance(value, str):
        return validate_item(value)

    return [validate_item(v) for v in value]


def validate_ttl(value: str | None) -> str | None:
    """Validate TTL format (Go duration: h, m, s)."""
    if value is None or value == "":
        return None

    pattern = re.compile(r"^(\d+h)?(\d+m)?(\d+s)?$")
    if not pattern.fullmatch(value):
        raise typer.BadParameter(
            "Invalid TTL. Use Go duration parts (h,m,s) only. Examples: 30m, 1h, 2h15m, 45s"
        )
    return value


def parse_content_range(value: str) -> tuple[int, int | None, int | None] | None:
    """Parse HTTP Content-Range header."""
    m = re.match(r"^bytes (\d+)-(\d+|\*)/(\d+|\*)$", value)
    if not m:
        return None
    start, end, total = m.groups()
    return (
        int(start),
        (None if end == "*" else int(end)),
        (None if total == "*" else int(total)),
    )


def parse_regex(value: str) -> re.Pattern:
    """Parse and validate a regex pattern."""
    try:
        pattern = re.compile(value)
    except re.error as e:
        raise typer.BadParameter(f"{e}")
    return pattern


@overload
async def send_gh_request(
    session: aiohttp.ClientSession,
    method: Literal["GET"],
    url: str,
    console: Console,
    **kwargs: Any,
) -> dict[str, Any]: ...


@overload
async def send_gh_request(
    session: aiohttp.ClientSession,
    method: Literal["DELETE", "POST", "PATCH", "PUT", "HEAD", "OPTIONS"],
    url: str,
    console: Console,
    **kwargs: Any,
) -> int: ...


async def send_gh_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    console: Console,
    **kwargs: Any,
) -> dict[str, Any] | int:
    """Send a GitHub API request with rate limiting and retry logic."""
    sem = asyncio.Semaphore(20)
    max_retries = 3
    attempt = 0
    while True:
        attempt += 1

        async with sem:
            async with session.request(method, url, **kwargs) as resp:
                if resp.status in (403, 429):
                    reset_time = int(resp.headers.get("x-ratelimit-reset", 0))
                    current_time = int(time.time())
                    sleep_time = max(reset_time - current_time, 0) + 120

                    if sleep_time < 5 and resp.status == 429:
                        sleep_time = int(resp.headers.get("Retry-After", 120))

                    msg = f"[yellow]Rate limit hit ({resp.status}). Waiting {sleep_time:.0f}s until reset...[/yellow]"
                    console.print(msg)
                    await asyncio.sleep(sleep_time)
                    continue

                if resp.status >= 400:
                    if attempt >= max_retries:
                        console.print(
                            f"[bold red]Permanent failure after {max_retries} attempts. Raising error for {resp.status}.[/bold red]"
                        )
                        resp.raise_for_status()

                    console.print(
                        f"[red]Error {resp.status} encountered (Attempt {attempt}/{max_retries}). Retrying in 5s.[/red]"
                    )
                    await asyncio.sleep(5)
                    continue

                if method == "GET":
                    resp.raise_for_status()
                    return await resp.json()
                else:
                    return resp.status


def validate_repo_format(value: str) -> str:
    """Validate GitHub repository format (owner/repo)."""
    error_msg = f"Invalid repository format: '{value}'. Must be in 'owner/repo' format (e.g., 'google/typer')."

    if value.count("/") != 1:
        raise typer.BadParameter(error_msg)

    owner, repo_name = value.split("/", 1)
    if not owner or not repo_name:
        raise typer.BadParameter(error_msg)

    if not re.match(r"^[\w-]+/[\w.-]+$", value):
        raise typer.BadParameter(error_msg)

    return value


def validate_github_token(value: str) -> str:
    """Validate GitHub token format."""
    min_len = 5
    max_len = 255
    if not (min_len <= len(value) <= max_len):
        raise typer.BadParameter(
            f"Token length must be between {min_len} and {max_len} characters. Found {len(value)} characters."
        )

    token_pattern = re.compile(r"^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]+$")
    if not token_pattern.match(value):
        error_msg = (
            "Invalid token format. It must start with one of the required prefixes "
            "(ghp_, github_pat_, gho_, ghu_, ghs_, or ghr_) "
            "and contain only alphanumeric characters or underscores ([A-Za-z0-9_]) for the remainder of the token."
        )
        raise typer.BadParameter(error_msg)

    return value


def validate_s3_key_prefix(ctx: typer.Context, param, value: str) -> str:
    """Validate S3 key prefix format."""
    if not value:
        return ""
    if value.startswith("/"):
        raise typer.BadParameter(
            "S3 key prefix must not start with '/'. Example: backups/2026/"
        )

    pattern = re.compile(r"^[A-Za-z0-9/_\-.]+$")
    if not pattern.match(value):
        raise typer.BadParameter(
            "S3 key prefix contains invalid characters. "
            "Allowed: letters, numbers, '/', '-', '_', '.'"
        )

    if not value.endswith("/"):
        value = value + "/"

    return value


def validate_vault_address(ctx: typer.Context, param, value: str):
    import validators
    from click.core import ParameterSource

    source = ctx.get_parameter_source(param.name)
    if source == ParameterSource.DEFAULT:
        typer.secho(
            f"WARNING! VAULT_ADDR and {param.opts[0]} unset. Defaulting to {value}.",
            fg=typer.colors.YELLOW,
        )
    else:
        if not validators.url(value):
            raise typer.BadParameter(f"Invalid Vault address URL: {value!r}")
    return value


def handle_vault_authentication(
    client: hvac.Client,
    vault_token: str | None,
    k8s_role: str | None = None,
    k8s_mount_point: str = "kubernetes",
    k8s_token_path: Path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token"),
) -> hvac.Client:
    from hvac.exceptions import InvalidRequest, VaultError

    TOKEN_FILEPATH = Path.home() / ".vault-token"

    if vault_token:
        client.token = vault_token
        return client

    if TOKEN_FILEPATH.exists():
        if saved_token := TOKEN_FILEPATH.read_text().strip():
            client.token = saved_token
            return client

    if k8s_role:
        typer.echo(f"Attempting Kubernetes Auth for role: {k8s_role}...")

        if not k8s_token_path.exists():
            typer.secho(
                f"K8s token file not found at {k8s_token_path}. Cannot proceed with K8s Auth.",
                fg=typer.colors.RED,
                bold=True,
            )
            raise typer.Exit(code=1)

        jwt = k8s_token_path.read_text().strip()

        try:
            client.auth.kubernetes.login(
                role=k8s_role, jwt=jwt, mount_point=k8s_mount_point
            )
            return client

        except (InvalidRequest, VaultError) as e:
            typer.secho(f"Kubernetes Auth Failed: {e}", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=1)

    typer.secho(
        "No valid Vault authentication method found.",
        fg=typer.colors.RED,
        bold=True,
    )
    raise typer.Exit(code=1)


def create_s3_client(bucket_name: str):
    import boto3
    import botocore.exceptions

    try:
        session = boto3.Session()
        s3_client: S3Client = cast(S3Client, session.client("s3"))
        s3_client.head_bucket(Bucket=bucket_name)
        return s3_client

    except (
        botocore.exceptions.NoCredentialsError,
        botocore.exceptions.PartialCredentialsError,
    ) as e:
        typer.secho(
            f"Authentication Error: {e}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    except botocore.exceptions.ClientError as e:
        error_msg = e.response.get("Error", {}).get("Message", "")
        typer.secho(
            f"Error: S3 Head Bucket operation failed: {error_msg}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
