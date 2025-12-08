import asyncio
import aiohttp
from typing import Any, Literal, overload
from rich.console import Console
import time

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
