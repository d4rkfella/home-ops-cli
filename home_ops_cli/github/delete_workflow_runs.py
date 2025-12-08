import asyncio
from collections.abc import Awaitable
from datetime import datetime
from enum import Enum
from typing import Any

import aiohttp
import inquirer
import typer
from inquirer.themes import RedSolace
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from typing_extensions import Annotated

from ..utils import (
    async_command,
    send_gh_request,
    validate_github_token,
    validate_repo_format,
)


class WorkflowStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    ACTION_REQUIRED = "action_required"
    COMPLETED = "completed"
    IN_PROGRESS = "in_progress"
    QUEUED = "queued"


app = typer.Typer()


@app.command(help="Delete GitHub Actions workflow runs")
@async_command
async def delete_workflow_runs(
    token: Annotated[
        str,
        typer.Option(
            help="GitHub personal access token", callback=validate_github_token
        ),
    ],
    repo: Annotated[
        str,
        typer.Argument(
            help="GitHub repo in owner/repo format", callback=validate_repo_format
        ),
    ],
    status: Annotated[
        WorkflowStatus | None,
        typer.Option(help="Filter runs by status (e.g., 'success', 'failure')"),
    ] = None,
    limit: Annotated[
        int, typer.Option(help="Max number of workflow runs to fetch", min=1, max=1000)
    ] = 100,
    delete_all: Annotated[
        bool,
        typer.Option(
            help="Delete all workflow runs fetched (up to the --limit specified)"
        ),
    ] = False,
):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    api_base_url = f"https://api.github.com/repos/{repo}/actions/runs"
    per_page = 100

    async with aiohttp.ClientSession(headers=headers) as session:
        fetch_tasks: list[Awaitable[Any]] = []
        all_runs: list[dict[str, Any]] = []

        initial_params: dict[str, str | int] = {"per_page": 1, "page": 1}
        if status:
            initial_params["status"] = status.value

        console = Console()

        initial_data = await send_gh_request(
            session, "GET", api_base_url, console=console, params=initial_params
        )

        total_count = initial_data.get("total_count", 0)
        runs_to_fetch = min(total_count, limit)

        if runs_to_fetch == 0:
            typer.echo("No workflow runs found.")
            raise typer.Exit()

        pages_needed = (runs_to_fetch + per_page - 1) // per_page

        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            fetch_task_id = progress.add_task(
                f"Fetching workflow runs for {repo}", total=runs_to_fetch
            )

            for page in range(1, pages_needed + 1):
                params: dict[str, str | int] = {"per_page": per_page, "page": page}
                if status:
                    params["status"] = status.value

                fetch_tasks.append(
                    send_gh_request(
                        session,
                        "GET",
                        api_base_url,
                        console=progress.console,
                        params=params,
                    )
                )

            for coro in asyncio.as_completed(fetch_tasks):
                try:
                    data = await coro
                    runs = data.get("workflow_runs", [])

                    for run in runs:
                        if len(all_runs) >= limit:
                            break
                        all_runs.append(run)
                        progress.update(fetch_task_id, advance=1)

                    if len(all_runs) >= limit:
                        break
                except Exception as e:
                    progress.console.print(f"[red]Error fetching page: {e}[/red]")

            progress.update(fetch_task_id, completed=len(all_runs))

    all_runs.sort(key=lambda x: x["id"], reverse=True)

    CONCLUSION_MAP = {
        WorkflowStatus.SUCCESS.value: "GOOD",
        WorkflowStatus.FAILURE.value: "FAIL",
        WorkflowStatus.NEUTRAL.value: "NEUTR",
        WorkflowStatus.CANCELLED.value: "CANC",
        WorkflowStatus.SKIPPED.value: "SKIP",
        WorkflowStatus.TIMED_OUT.value: "TIMEOUT",
        WorkflowStatus.ACTION_REQUIRED.value: "ACT_REQ",
    }

    ids_to_delete: list[int] = []

    if not delete_all:
        choices_list: list[tuple[str, int]] = []

        for run in all_runs:
            s_date = datetime.fromisoformat(
                run["created_at"].replace("Z", "+00:00")
            ).strftime("%b %d %Y %H:%M")

            if run["status"] in ("queued", "in_progress"):
                conclusion = run["status"].upper()
            else:
                conclusion = CONCLUSION_MAP.get(
                    run["conclusion"], str(run["conclusion"]).upper()
                )

            display_str = (
                f"{conclusion:<8}"
                f"{s_date:<22}"
                f"{run['id']:<14}"
                f"{run['event']:<20}"
                f"{run['name']}"
            )

            choices_list.append((display_str, run["id"]))

        def autocomplete_runs(text: str, state: Any) -> list[tuple[str, int]]:
            if not text:
                return choices_list

            return [
                choice_tuple
                for choice_tuple in choices_list
                if text.lower() in choice_tuple[0].lower()
            ]

        questions = [
            inquirer.Checkbox(
                "selected_runs",
                message=f"Select workflows to delete (Total: {len(choices_list)})",
                choices=choices_list,
                carousel=True,
                autocomplete=autocomplete_runs,
            )
        ]
        answers = inquirer.prompt(questions, theme=RedSolace())

        if not answers:
            raise typer.Exit()

        ids_to_delete = answers["selected_runs"]

    else:
        ids_to_delete = [run["id"] for run in all_runs]

    async with aiohttp.ClientSession(headers=headers) as session:
        with Progress(
            TextColumn("[bold red]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            delete_task_id = progress.add_task(
                "Deleting workflow runs", total=len(ids_to_delete)
            )

            async def delete_run_task(run_id: int):
                del_url = f"{api_base_url}/{run_id}"
                line_str = f"Run ID: {run_id}"

                try:
                    status_code = await send_gh_request(
                        session, "DELETE", del_url, console=progress.console
                    )

                    if status_code == 204:
                        progress.console.print(f"Deleted: {line_str}")
                        progress.update(delete_task_id, advance=1)
                    else:
                        progress.console.print(
                            f"[red]Failed ({status_code}): {line_str}[/red]"
                        )
                except Exception as e:
                    progress.console.print(f"[red]Error deleting {run_id}: {e}[/red]")

            await asyncio.gather(*(delete_run_task(run_id) for run_id in ids_to_delete))
