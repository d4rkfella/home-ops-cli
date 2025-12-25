import asyncio
import random
import re
import time
import os
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any, Literal, overload
from pathlib import Path
import hvac

import aiohttp
import typer
from hvac.exceptions import InvalidRequest, VaultError
from kubernetes_asyncio import client, config  # type: ignore
from kubernetes_asyncio.config import ConfigException
from kubernetes_asyncio.dynamic import DynamicClient  # type: ignore
from rich.console import Console

from .exceptions import RetryLimitExceeded


def async_command(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


async def retry_with_backoff(
    fn, *args, retries=5, base_delay=2, console=None, **kwargs
):
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
    try:
        await config.load_kube_config()
        print("Configuration loaded from kubeconfig.")
    except ConfigException:
        try:
            config.load_incluster_config()
            print("Configuration loaded from in-cluster service account.")
        except ConfigException as e:
            raise RuntimeError(f"Could not load Kubernetes configuration: {e}")
    async with client.ApiClient() as api_client:
        dyn_client = await DynamicClient(api_client)
        yield dyn_client


def validate_kube_rfc1123_label(value: str | list[str]) -> str | list[str]:
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
    if value is None or value == "":
        return None

    pattern = re.compile(r"^(\d+h)?(\d+m)?(\d+s)?$")
    if not pattern.fullmatch(value):
        raise typer.BadParameter(
            "Invalid TTL. Use Go duration parts (h,m,s) only. Examples: 30m, 1h, 2h15m, 45s"
        )
    return value


def parse_content_range(value: str) -> tuple[int, int | None, int | None] | None:
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

                    msg = f"[yellow]Rate limit hit ({resp.status}). Waiting {
                        sleep_time:.0f}s until reset...[/yellow]"
                    console.print(msg)
                    await asyncio.sleep(sleep_time)
                    continue

                if resp.status >= 400:
                    if attempt >= max_retries:
                        console.print(
                            f"[bold red]Permanent failure after {
                                max_retries
                            } attempts. Raising error for {resp.status}.[/bold red]"
                        )
                        resp.raise_for_status()

                    console.print(
                        f"[red]Error {resp.status} encountered (Attempt {attempt}/{
                            max_retries
                        }). Retrying in 5s.[/red]"
                    )
                    await asyncio.sleep(5)
                    continue

                if method == "GET":
                    resp.raise_for_status()
                    return await resp.json()
                else:
                    return resp.status


def validate_repo_format(value: str) -> str:
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
    min_len = 5
    max_len = 255
    if not (min_len <= len(value) <= max_len):
        raise typer.BadParameter(
            f"Token length must be between {min_len} and {max_len} characters. Found {
                len(value)
            } characters."
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


def handle_vault_authentication(
    client: hvac.Client,
    vault_url: str,
    vault_token: str | None,
    k8s_role: str | None,
    k8s_mount_point: str,
) -> hvac.Client:
    K8S_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    TOKEN_FILEPATH = Path.home() / ".vault-token"
    typer.echo(f"Connecting to Vault at: {vault_url}...")
    if k8s_role:
        typer.echo(f"Attempting Kubernetes Auth for role: {k8s_role}...")

        if not os.path.exists(K8S_JWT_PATH):
            typer.secho(
                f"K8s JWT file not found at {K8S_JWT_PATH}. Cannot proceed with K8s Auth.",
                fg=typer.colors.RED,
                bold=True,
            )
            raise typer.Exit(code=1)

        with open(K8S_JWT_PATH, "r") as f:
            jwt = f.read().strip()

        try:
            client.auth.kubernetes.login(
                role=k8s_role, jwt=jwt, mount_point=k8s_mount_point
            )
            return client

        except (InvalidRequest, VaultError) as e:
            typer.secho(f"Kubernetes Auth Failed: {e}", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=1)
        except Exception as e:
            typer.secho(
                f"Unexpected Error during Kubernetes Auth: {e}",
                fg=typer.colors.RED,
                bold=True,
            )
            raise typer.Exit(code=1)

    if vault_token:
        client.token = vault_token
        return client

    if TOKEN_FILEPATH.exists():
        saved_token = TOKEN_FILEPATH.read_text().strip()
        if saved_token:
            client.token = saved_token
            return client
