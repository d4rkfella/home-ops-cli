import asyncio
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

import typer
from kubernetes_asyncio import watch
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from typing_extensions import Annotated

from ..utils import async_command, dynamic_client


@dataclass(frozen=True)
class ResourceSpec:
    rtype: str
    name: str
    namespace: str | None
    kind: str
    api_version: str
    readiness: Callable[[object], bool]


RESOURCE_TYPES = {
    "crd": {
        "kind": "CustomResourceDefinition",
        "api_version": "apiextensions.k8s.io/v1",
        "needs_namespace": False,
        "readiness": lambda obj: True,
    },
    "deployment": {
        "kind": "Deployment",
        "api_version": "apps/v1",
        "needs_namespace": True,
        "readiness": lambda obj: (getattr(obj.status, "readyReplicas", 0) or 0)
        >= (getattr(obj.spec, "replicas", 0) or 0),
    },
    "daemonset": {
        "kind": "DaemonSet",
        "api_version": "apps/v1",
        "needs_namespace": True,
        "readiness": lambda obj: (getattr(obj.status, "numberReady", 0) or 0)
        >= (getattr(obj.status, "desiredNumberScheduled", 0) or 0),
    },
    "statefulset": {
        "kind": "StatefulSet",
        "api_version": "apps/v1",
        "needs_namespace": True,
        "readiness": lambda obj: (getattr(obj.status, "readyReplicas", 0) or 0)
        >= (getattr(obj.spec, "replicas", 0) or 0),
    },
}


def parse_resource(arg: str) -> set[ResourceSpec]:
    if "@" in arg:
        resource_part, namespace = arg.split("@", 1)
    else:
        resource_part, namespace = arg, None

    if "/" not in resource_part:
        raise typer.BadParameter(
            "Resource must be in form type/name1[,name2,...][@namespace]"
        )

    rtype, names_str = resource_part.split("/", 1)
    names = names_str.split(",")

    if rtype not in RESOURCE_TYPES:
        raise typer.BadParameter(f"Unknown resource type: {rtype}")

    info = RESOURCE_TYPES[rtype]

    if namespace and not info["needs_namespace"]:
        raise typer.BadParameter(f"Resource {rtype} should not have a namespace")

    if info["needs_namespace"] and not namespace:
        raise typer.BadParameter(f"Resource {rtype} requires a namespace")

    return {
        ResourceSpec(
            rtype=rtype,
            name=name,
            namespace=namespace,
            kind=info["kind"],
            api_version=info["api_version"],
            readiness=info["readiness"],
        )
        for name in names
    }


async def wait_for_resources_group(
    dyn,
    resources: set[ResourceSpec],
    spinner_progress: Progress,
    overall_progress: Progress,
    overall_task: TaskID,
    timeout: int,
):
    if not resources:
        return

    first = next(iter(resources))
    kind = first.kind
    api_version = first.api_version
    namespace = first.namespace
    readiness_checker = first.readiness

    api = await dyn.resources.get(api_version=api_version, kind=kind)
    remaining = set(r.name for r in resources)
    watcher = watch.Watch()

    resource_tasks = {
        r.name: spinner_progress.add_task(
            f"Waiting for {kind} {r.name} in namespace {namespace}", total=None
        )
        for r in resources
    }

    async def _watch_loop():
        async for event in api.watch(namespace=namespace, watcher=watcher):
            obj = event["object"]
            name = obj.metadata.name
            if name not in remaining:
                continue

            if readiness_checker(obj):
                remaining.remove(name)
                spinner_progress.console.print(
                    f"[green]✔ {kind} {name} in namespace {namespace} is ready[/green]"
                )
                spinner_progress.remove_task(resource_tasks[name])
                overall_progress.update(overall_task, advance=1)

                if not remaining:
                    break

    try:
        await asyncio.wait_for(_watch_loop(), timeout=timeout)
    except asyncio.TimeoutError:
        spinner_progress.console.print(
            f"[bold red]Timeout waiting for {kind} resources: {', '.join(remaining)}[/bold red]"
        )
        raise typer.Exit(code=1)
    finally:
        await watcher.close()


app = typer.Typer()


@app.command(
    help=(
        "Watches specified Kubernetes workloads (Deployments, DaemonSets, StatefulSets) "
        "and/or CustomResourceDefinitions (CRDs), and waits for them to become ready. "
        "A readiness check is performed for each resource based on its type:\n\n"
        "• Deployments and StatefulSets are considered ready when all replicas are available.\n"
        "• DaemonSets are ready when all scheduled pods are available.\n"
        "• CRDs are considered ready immediately (existence only).\n\n"
        "Resources must be specified in the form type/name[@namespace], e.g.:\n"
        "  deployment/my-app@default\n"
        "  crd/mycrd\n\n"
        "Multiple resources can be passed, optionally in different namespaces. "
        "An overall progress bar shows total progress, while individual spinners show per-resource readiness."
    )
)
@async_command
async def wait(
    resources: Annotated[
        list[str],
        typer.Argument(help="Resources in form type/name[@namespace]"),
    ],
    timeout: Annotated[int, typer.Option(help="Timeout in seconds")] = 240,
):
    async with dynamic_client() as dyn:
        parsed_resources = {res for r in resources for res in parse_resource(r)}

        groups: defaultdict[tuple[str, str, str | None], set[ResourceSpec]] = (
            defaultdict(set)
        )
        for r in parsed_resources:
            groups[(r.kind, r.api_version, r.namespace)].add(r)

        overall_progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        )

        spinner_progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
        )

        with overall_progress, spinner_progress:
            overall_task = overall_progress.add_task(
                "Waiting for all resources to become ready ...",
                total=len(parsed_resources),
            )

            await asyncio.gather(
                *(
                    wait_for_resources_group(
                        dyn=dyn,
                        resources=group,
                        spinner_progress=spinner_progress,
                        overall_progress=overall_progress,
                        overall_task=overall_task,
                        timeout=timeout,
                    )
                    for group in groups.values()
                )
            )
