import asyncio
import random
import re
import time
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from functools import wraps
from typing import Any, Literal, cast, overload

import aiohttp
import typer
from dateutil.parser import parse as parse_datetime
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


def select_snapshot(
    contents: Sequence[Mapping[str, object]], filename_regex: re.Pattern | None
) -> str:
    if filename_regex:
        valid_objects: list[Mapping[str, object]] = []

        for o in contents:
            key = o.get("Key")
            if not isinstance(key, str):
                continue

            match = filename_regex.match(key)
            if not match:
                continue

            ts_str = match.group(1)
            try:
                ts = parse_datetime(ts_str)
                valid_objects.append({"Key": key, "Timestamp": ts})
            except ValueError:
                continue

        if not valid_objects:
            raise ValueError(
                "No valid snapshots found matching the filename regex with parseable timestamp"
            )

        latest_obj = max(valid_objects, key=lambda o: cast(datetime, o["Timestamp"]))
        return cast(str, latest_obj["Key"])

    else:
        valid_objects: list[Mapping[str, object]] = [
            o
            for o in contents
            if isinstance(o.get("Key"), str)
            and isinstance(o.get("LastModified"), datetime)
        ]
        if not valid_objects:
            raise RuntimeError("No valid snapshots with LastModified found")

        latest_obj = max(valid_objects, key=lambda o: cast(datetime, o["LastModified"]))
        return cast(str, latest_obj["Key"])


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
