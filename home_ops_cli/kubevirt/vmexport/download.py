from __future__ import annotations

import asyncio
import base64
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlparse, urlunparse
import os

import aiofiles
import aiogzip
import aiohttp
import typer
from kr8s.objects import object_from_spec
from kr8s.portforward import PortForward
from kubernetes_asyncio import client  # type: ignore
from kubernetes_asyncio.client.exceptions import ApiException  # type: ignore
from kubernetes_asyncio.dynamic import DynamicClient  # type: ignore
from kubevirt import ApiClient, Configuration, DefaultApi
from kubevirt.models import (
    K8sIoApiCoreV1TypedLocalObjectReference,
    K8sIoApimachineryPkgApisMetaV1DeleteOptions,
    K8sIoApimachineryPkgApisMetaV1ObjectMeta,
    V1beta1VirtualMachineExport,
    V1beta1VirtualMachineExportSpec,
    V1beta1VirtualMachineExportStatus,
)
from kubevirt.rest import ApiException as KubeVirtApiException
from textual.color import Gradient
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from typing_extensions import Annotated

from ...exceptions import RetryableDownloadError, VMExportAlreadyExistsError
from ...utils import async_command, dynamic_client, parse_content_range, validate_ttl

VMImageFormat = Literal["gzip", "raw", "qcow2"]
ManifestFormat = Literal["yaml", "json"]


GRADIENT = Gradient(
    (0.0, "#A00000"),
    (0.33, "#FF7300"),
    (0.66, "#4caf50"),
    (1.0, "#8bc34a"),
    quality=50,
)


@dataclass
class VMExportInfo:
    volume: str | None
    namespace: str
    name: str
    download_retries: int
    readiness_timeout: int
    format: str
    sparsify: bool
    manifest_output_format: str
    output_file: Path | None
    local_port: int
    service_url: str | None
    should_create: bool
    ttl: str | None
    insecure: bool
    keep_vme: bool
    delete_vme: bool
    export_manifest: bool
    include_secret: bool
    decompress: bool
    port_forward: bool
    export_source: K8sIoApiCoreV1TypedLocalObjectReference | None
    labels: dict[str, str]
    annotations: dict[str, str]


app = typer.Typer(
    help="vmexport CLI (Typer port of KubeVirt virtctl vmexport download)"
)


TRANSIENT_HTTP_STATUSES = {500, 502, 503, 504}
CHUNK_SIZE_DEFAULT = 10 * 1024 * 1024
PROCESSING_WAIT_INTERVAL = 2
EXPORT_TOKEN_HEADER = "x-kubevirt-export-token"


async def wait_for_service(dyn, namespace: str, service_name: str, timeout: int = 30):
    for _ in range(timeout):
        try:
            svc = await dyn.resources.get(api_version="v1", kind="Service")
            service = await svc.get(name=service_name, namespace=namespace)
            if service:
                return service
        except ApiException as e:
            if e.status != 404:
                raise
        await asyncio.sleep(1)
    raise TimeoutError(f"Service {service_name} not ready after {timeout}s")


async def get_pod_for_service(dyn, namespace: str, service):
    selector = service.spec.selector
    selector_str = ",".join([f"{k}={v}" for k, v in selector.items()])
    pods_res = await dyn.resources.get(api_version="v1", kind="Pod")
    pods = await pods_res.get(namespace=namespace, label_selector=selector_str)
    if not pods.items:
        raise RuntimeError(f"No pods found for service {service.metadata.name}")
    return pods.items[0]


async def translate_service_port_to_target_port(
    service: Any, pod: Any, remote_port: int | str, local_port: int
) -> int:
    service_port_obj = None
    remote_port_str = str(remote_port)

    for port in getattr(service.spec, "ports", []):
        if (
            str(getattr(port, "port", "")) == remote_port_str
            or getattr(port, "name", "") == remote_port_str
        ):
            service_port_obj = port
            break

    if not service_port_obj:
        raise ValueError(
            f"Service '{service.metadata.name}' does not expose port '{remote_port_str}'."
        )

    target_port = getattr(service_port_obj, "target_port", None) or getattr(
        service_port_obj, "targetPort", None
    )
    if not target_port:
        return int(service_port_obj.port)

    if isinstance(target_port, int):
        return target_port

    if isinstance(target_port, str):
        target_port_name = target_port
        for container in getattr(pod.spec, "containers", []):
            for container_port in getattr(container, "ports", []):
                if getattr(container_port, "name", "") == target_port_name:
                    return int(container_port.container_port)

        raise ValueError(
            f"Named targetPort '{target_port_name}' not found in any container in Pod '{pod.metadata.name}'."
        )

    return int(service_port_obj.port)


async def setup_port_forward(dyn, vme_info: VMExportInfo) -> PortForward:
    service_name = f"virt-export-{vme_info.name}"
    service = await wait_for_service(dyn, vme_info.namespace, service_name)

    pod = await get_pod_for_service(dyn, vme_info.namespace, service)
    pod_dict = pod.to_dict()

    target_port = await translate_service_port_to_target_port(
        service, pod, remote_port=443, local_port=vme_info.local_port
    )

    pod = object_from_spec(pod_dict)

    pf = PortForward(pod, remote_port=target_port, local_port=vme_info.local_port)
    pf.start()

    if vme_info.local_port == 0:
        while pf.local_port == 0:
            await asyncio.sleep(0.05)
        vme_info.service_url = f"127.0.0.1:{pf.local_port}"
    else:
        vme_info.service_url = f"127.0.0.1:{vme_info.local_port}"

    return pf


async def create_export_resource(
    kv_api: DefaultApi,
    vme_info: VMExportInfo,
) -> V1beta1VirtualMachineExport:
    export_body = V1beta1VirtualMachineExport(
        api_version="export.kubevirt.io/v1beta1",
        kind="VirtualMachineExport",
        metadata=K8sIoApimachineryPkgApisMetaV1ObjectMeta(
            name=vme_info.name,
            namespace=vme_info.namespace,
            labels=vme_info.labels or None,
            annotations=vme_info.annotations or None,
        ),
        spec=V1beta1VirtualMachineExportSpec(
            source=vme_info.export_source,
            ttl_duration=vme_info.ttl,
        ),
    )

    try:
        return cast(
            V1beta1VirtualMachineExport,
            await asyncio.to_thread(
                kv_api.create_namespaced_virtual_machine_export,
                namespace=vme_info.namespace,
                body=export_body,
            ),
        )
    except KubeVirtApiException as e:
        if getattr(e, "status", None) == 409:
            raise VMExportAlreadyExistsError(
                f"VMExport '{vme_info.name}' already exists"
            )
        raise


async def get_token_from_secret(
    client: DynamicClient, vmexport: V1beta1VirtualMachineExport
) -> str:
    if vmexport.status and vmexport.status.token_secret_ref:
        secret_name = vmexport.status.token_secret_ref
    else:
        raise RuntimeError("Cannot read tokenSecretRef from VMExport resource")

    secrets_api = await client.resources.get(api_version="v1", kind="Secret")

    try:
        secret_resource = await secrets_api.get(
            name=secret_name,
            namespace=cast(
                K8sIoApimachineryPkgApisMetaV1ObjectMeta, vmexport.metadata
            ).namespace,
        )
    except Exception as e:
        raise RuntimeError(f"Error fetching secret '{secret_name}': {e}")

    data = secret_resource.get("data", {}) or {}
    token_b64 = data.get("token")
    if not token_b64:
        raise RuntimeError("Token key missing in secret data.")
    return base64.b64decode(token_b64).decode("utf-8")


async def get_virtual_machine_export(
    kv_api: DefaultApi, vme_info: VMExportInfo
) -> V1beta1VirtualMachineExport | None:
    try:
        return cast(
            V1beta1VirtualMachineExport,
            await asyncio.to_thread(
                kv_api.read_namespaced_virtual_machine_export,
                vme_info.name,
                vme_info.namespace,
            ),
        )
    except KubeVirtApiException as e:
        if getattr(e, "status", None) == 404:
            return None
        raise


async def wait_for_export_ready(
    kv_api: DefaultApi,
    vme_info: VMExportInfo,
    console: Console | None = None,
):
    console = console or Console()

    is_ci = os.getenv("GITHUB_ACTIONS") == "true" or not console.is_terminal

    with Progress(
        SpinnerColumn() if not is_ci else TextColumn("•"),
        TextColumn("[dim]{task.fields[msg]}"),
        console=console,
        transient=False,
        auto_refresh=not is_ci,
    ) as progress:
        task = progress.add_task(
            "wait",
            msg=f"Checking VMExport status...",
            total=None,
        )

        start = time.time()
        last_refresh = 0.0

        while time.time() - start < vme_info.readiness_timeout:
            vme = await get_virtual_machine_export(kv_api, vme_info)

            if vme is None:
                current_msg = f"couldn't get VM Export {vme_info.name}, waiting for it to be created..."
            else:
                status = getattr(vme, "status", None)
                if not status:
                    current_msg = "waiting for export status..."
                else:
                    phase = getattr(status, "phase", None)
                    if phase != "Ready":
                        current_msg = f"VM Export '{vme_info.name}' is not ready, waiting... (Current status: {phase})"
                    else:
                        links = getattr(status, "links", None)
                        if not links or (
                            not getattr(links, "external", None)
                            and not getattr(links, "internal", None)
                        ):
                            current_msg = "[yellow]waiting for VM Export '{vme_info.name}' links to be available...[/yellow]"
                        else:
                            progress.update(task, msg="VMExport is ready!")
                            return

            progress.update(task, msg=current_msg)

            if is_ci:
                if time.time() - last_refresh >= 5.0:
                    progress.refresh()
                    last_refresh = time.time()

            await asyncio.sleep(PROCESSING_WAIT_INTERVAL)

    raise TimeoutError(
        f"VMExport '{vme_info.name}' did not reach Ready state within {vme_info.readiness_timeout}s"
    )


def _replace_url_with_service_url(manifest_url: str, service_url: str | None) -> str:
    if service_url:
        parsed = urlparse(manifest_url)
        parsed = parsed._replace(netloc=service_url)
        return urlunparse(parsed)
    return manifest_url


async def get_url_from_vmexport(
    vmexport: V1beta1VirtualMachineExport, vme_info: VMExportInfo
) -> str:
    status = cast(V1beta1VirtualMachineExportStatus, vmexport.status)
    if vme_info.service_url:
        links = getattr(status.links, "internal", None)
    else:
        links = getattr(status.links, "external", None)

    metadata = cast(K8sIoApimachineryPkgApisMetaV1ObjectMeta, vmexport.metadata)

    if not links or not getattr(links, "volumes", None):
        raise ValueError(
            f"unable to access the volume info from '{metadata.namespace}/{metadata.name}' VirtualMachineExport"
        )

    volumes = links.volumes
    volume_number = len(volumes)

    if volume_number > 1 and not vme_info.volume:
        raise ValueError(
            f"detected more than one downloadable volume in '{metadata.namespace}/{metadata.name}' VirtualMachineExport: "
            "Select the expected volume using the --volume flag"
        )

    download_url = ""
    selected_format = None

    for export_volume in volumes:
        if volume_number == 1 or export_volume.name == vme_info.volume:
            for fmt in export_volume.formats:
                if fmt.format in ["gzip", "ArchiveGz", "raw"]:
                    download_url = _replace_url_with_service_url(
                        fmt.url, vme_info.service_url
                    )
                    selected_format = fmt.format
                if fmt.format in ["gzip", "ArchiveGz"]:
                    break

    if selected_format == "raw":
        vme_info.decompress = False

    if not download_url:
        raise ValueError(
            f"unable to get a valid URL from '{metadata.namespace}/{metadata.name}' VirtualMachineExport"
        )

    return download_url


def get_manifest_urls_from_vmexport(
    vmexport: V1beta1VirtualMachineExport, vme_info: VMExportInfo
):
    res = {}

    status = cast(V1beta1VirtualMachineExportStatus, vmexport.status)
    metadata = cast(K8sIoApimachineryPkgApisMetaV1ObjectMeta, vmexport.metadata)
    if not vme_info.service_url:
        links = getattr(status, "links", None)
        external = getattr(links, "external", None) if links else None
        manifests = getattr(external, "manifests", None) if external else None
        if not manifests:
            raise ValueError(
                f"unable to access the manifest info from '{metadata.namespace}/{metadata.name}' VirtualMachineExport"
            )
        for manifest in manifests:
            res[manifest.type] = manifest.url

    else:
        links = getattr(status, "links", None)
        internal = getattr(links, "internal", None) if links else None
        manifests = getattr(internal, "manifests", None) if internal else None
        if not manifests:
            raise ValueError(
                f"unable to access the manifest info from '{metadata.namespace}/{metadata.name}' VirtualMachineExport"
            )
        for manifest in manifests:
            parsed = urlparse(manifest.url)
            new_url = parsed._replace(netloc=vme_info.service_url)
            res[manifest.type] = urlunparse(new_url)

    return res


async def print_request_body(
    client: DynamicClient,
    vmexport: V1beta1VirtualMachineExport,
    vme_info: VMExportInfo,
    manifest_url: str,
    headers: dict,
) -> None:
    token = await get_token_from_secret(client, vmexport)
    headers = headers.copy()
    headers[EXPORT_TOKEN_HEADER] = token
    connector = aiohttp.TCPConnector(ssl=not vme_info.insecure)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(manifest_url, headers=headers) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Failed to fetch manifest: HTTP {resp.status}")
                content = await resp.text()

        if output_file := vme_info.output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
        else:
            print(content)

    except Exception as e:
        raise RuntimeError(f"Error fetching or printing manifest: {e}") from e


async def get_virtual_machine_manifest(client: DynamicClient, vmexport, vme_info):
    manifest_dict = get_manifest_urls_from_vmexport(vmexport, vme_info)
    if not manifest_dict:
        raise RuntimeError("Failed to get manifest dictionary from VMExport")

    headers = {"Accept": "application/yaml"}

    if str(vme_info.manifest_output_format).lower() == "json":
        headers["Accept"] = "application/json"

    await print_request_body(client, vmexport, vme_info, manifest_dict["all"], headers)
    if vme_info.include_secret:
        await print_request_body(
            client, vmexport, vme_info, manifest_dict["auth-header-secret"], headers
        )


async def download_volume(
    client: DynamicClient,
    vmexport: V1beta1VirtualMachineExport,
    vme_info: VMExportInfo,
    console: Console,
    dest_path: Path,
    chunk_size: int = CHUNK_SIZE_DEFAULT,
) -> None:
    url = await get_url_from_vmexport(vmexport, vme_info)
    token = await get_token_from_secret(client, vmexport)

    attempt = 0

    while attempt <= vme_info.download_retries:
        try:
            headers = {EXPORT_TOKEN_HEADER: token}

            timeout = aiohttp.ClientTimeout(total=None, connect=60, sock_read=300)

            connector = aiohttp.TCPConnector(ssl=not vme_info.insecure)
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status in TRANSIENT_HTTP_STATUSES:
                        raise RetryableDownloadError(
                            f"Server returned transient error: {resp.status} {resp.reason}"
                        )

                    resp.raise_for_status()

                    total_size = None
                    cl = resp.headers.get("Content-Length")
                    if cl and cl.isdigit():
                        total_size = int(cl)
                    else:
                        cr = resp.headers.get("Content-Range")
                        if cr:
                            parsed = parse_content_range(cr)
                            if parsed:
                                _, _, total = parsed
                                total_size = total

                    is_ci = (
                        os.getenv("GITHUB_ACTIONS") == "true" or not console.is_terminal
                    )

                    with Progress(
                        SpinnerColumn() if not is_ci else TextColumn("•"),
                        TextColumn(
                            "[bold blue]Downloading vm disk image...[/bold blue]"
                        ),
                        DownloadColumn(),
                        TransferSpeedColumn(),
                        TimeRemainingColumn(),
                        console=console,
                        transient=False,
                        auto_refresh=not is_ci,
                    ) as dl_progress:
                        task_id = dl_progress.add_task(
                            "download",
                            filename=cast(Path, vme_info.output_file).name,
                            total=total_size,
                        )

                        last_refresh = time.time()

                        if vme_info.decompress:
                            async with aiofiles.open(dest_path, "wb") as f_out:
                                async with aiogzip.AsyncGzipFile(
                                    filename=None, mode="rb", fileobj=resp.content
                                ) as gz:
                                    while True:
                                        chunk = await gz.read(chunk_size)
                                        if not chunk:
                                            break
                                        chunk_bytes = cast(bytes, chunk)
                                        await f_out.write(chunk_bytes)
                                        dl_progress.update(
                                            task_id, advance=len(chunk_bytes)
                                        )

                                        if is_ci:
                                            if time.time() - last_refresh >= 5.0:
                                                dl_progress.refresh()
                                                last_refresh = time.time()
                        else:
                            async with aiofiles.open(dest_path, "wb") as f_out:
                                async for chunk in resp.content.iter_chunked(
                                    chunk_size
                                ):
                                    await f_out.write(chunk)
                                    dl_progress.update(task_id, advance=len(chunk))

                                    if is_ci:
                                        if time.time() - last_refresh >= 5.0:
                                            dl_progress.refresh()
                                            last_refresh = time.time()
            return

        except (RetryableDownloadError, aiohttp.ClientConnectorError) as e:
            attempt += 1
            if attempt <= vme_info.download_retries:
                console.print(
                    f"[yellow]retry {attempt}/{vme_info.download_retries} due to transient error: {e}[/yellow]"
                )
                await asyncio.sleep(2)
                continue
            console.print(
                f"[bold red]download failed after {vme_info.download_retries + 1} attempts[/bold red]"
            )
            raise

        except aiohttp.ClientResponseError as e:
            status = getattr(e, "status", None)
            if (
                status in TRANSIENT_HTTP_STATUSES
                and attempt < vme_info.download_retries
            ):
                attempt += 1
                console.print(
                    f"[yellow]retry {attempt}/{vme_info.download_retries} due to transient HTTP error {status}[/yellow]"
                )
                await asyncio.sleep(2)
                continue
            console.print(f"[bold red]http error: {status} {e}[/bold red]")
            raise

        except Exception as e:
            console.print(
                f"[bold red]download failed: {type(e).__name__}: {e}[/bold red]"
            )
            raise


def convert_to_qcow2(
    source: Path, dest: Path, console: Console, sparsify: bool = True
) -> bool:
    tool = "virt-sparsify" if sparsify else "qemu-img"
    if not shutil.which(tool):
        console.print(f"[bold red]Error: '{tool}' not found in PATH.[/bold red]")
        return False

    if sparsify:
        cmd = [
            "virt-sparsify",
            "--machine-readable",
            "--convert",
            "qcow2",
            "--compress",
            str(source),
            str(dest),
        ]
    else:
        cmd = [
            "qemu-img",
            "convert",
            "-p",
            "-f",
            "raw",
            "-O",
            "qcow2",
            "-c",
            str(source),
            str(dest),
        ]

    try:
        is_ci = os.getenv("GITHUB_ACTIONS") == "true" or not console.is_terminal

        with Progress(
            SpinnerColumn() if not is_ci else TextColumn("•"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
            auto_refresh=not is_ci,
        ) as progress:
            task_id = progress.add_task(f"Converting image to qcow2 format", total=100)

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )

            qemu_re = re.compile(r"\((\d+\.\d+)/100%\)")
            sparsify_re = re.compile(r"progress:\s+(\d+)/100")

            last_refresh = time.time()

            if process.stdout is not None:
                for line in process.stdout:
                    clean_line = line.strip()
                    if not clean_line:
                        continue

                    if sparsify:
                        match = sparsify_re.search(clean_line)
                        if match:
                            progress.update(task_id, completed=float(match.group(1)))
                        else:
                            progress.update(
                                task_id, description=f"[dim]{clean_line[:50]}..."
                            )
                    else:
                        match = qemu_re.search(clean_line)
                        if match:
                            progress.update(task_id, completed=float(match.group(1)))

                    if is_ci:
                        if time.time() - last_refresh >= 5.0:
                            progress.refresh()
                            last_refresh = time.time()

            process.wait()

            if process.returncode != 0:
                console.print(
                    f"[bold red]Conversion failed with exit code {process.returncode}[/bold red]"
                )
                return False

        console.print(f"[green]✓ Successfully converted to {dest.name}[/green]")
        return True

    except Exception as e:
        console.print(f"[bold red]Conversion error: {e}[/bold red]")
        return False


def parse_labels_annotations(items: list[str]) -> dict[str, str]:
    result = {}
    for item in items:
        if "=" in item:
            key, value = item.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def convert_list_to_dict(items: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        if "=" in item:
            key, value = item.split("=", 1)
            result[key] = value
    return result


def get_export_source(
    vm: str | None, snapshot: str | None, pvc: str | None
) -> K8sIoApiCoreV1TypedLocalObjectReference | None:
    if vm:
        return K8sIoApiCoreV1TypedLocalObjectReference(
            api_group="kubevirt.io",
            kind="VirtualMachine",
            name=vm,
        )
    if snapshot:
        return K8sIoApiCoreV1TypedLocalObjectReference(
            api_group="snapshot.kubevirt.io",
            kind="VirtualMachineSnapshot",
            name=snapshot,
        )
    if pvc:
        return K8sIoApiCoreV1TypedLocalObjectReference(
            api_group="",
            kind="PersistentVolumeClaim",
            name=pvc,
        )

    return None


def should_delete_vmexport(vme_info: VMExportInfo) -> bool:
    return not vme_info.export_manifest and (
        vme_info.delete_vme or (vme_info.should_create and not vme_info.keep_vme)
    )


@app.command()
@async_command
async def download(
    annotations: Annotated[
        list[str],
        typer.Option(
            help="Specify custom annotations to VM export object and its associated pod",
            default_factory=list,
        ),
    ],
    labels: Annotated[
        list[str],
        typer.Option(
            help="Specify custom labels to VM export object and its associated pod",
            default_factory=list,
        ),
    ],
    name: Annotated[str, typer.Argument(help="Name of VMExport resource")],
    namespace: Annotated[str, typer.Option("--namespace", "-n")] = "default",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Output path")
    ] = None,
    ttl: Annotated[
        str | None,
        typer.Option(
            callback=validate_ttl,
            help="The time after the export was created that it is eligible to be automatically deleted, defaults to 2 hours by the server side if not specified",
        ),
    ] = None,
    readiness_timeout: Annotated[
        int, typer.Option(help="Specify maximum wait for VM export object to be ready")
    ] = 120,
    delete_vme: Annotated[
        bool,
        typer.Option(
            "--delete-vme",
            help="Specifies that the vmexport object should always be deleted after the download finishes.",
        ),
    ] = False,
    keep_vme: Annotated[
        bool,
        typer.Option(
            "--keep-vme",
            help="Specifies that the vmexport object should always be retained after the download finishes.",
        ),
    ] = False,
    vm: Annotated[
        str | None,
        typer.Option(
            help="Sets VirtualMachine as vmexport kind and specifies the vm name."
        ),
    ] = None,
    pvc: Annotated[
        str | None,
        typer.Option(
            help="Sets PersistentVolumeClaim as vmexport kind and specifies the PVC name."
        ),
    ] = None,
    snapshot: Annotated[
        str | None,
        typer.Option(
            help="Sets VirtualMachineSnapshot as vmexport kind and specifies the snapshot name."
        ),
    ] = None,
    service_url: Annotated[
        str | None,
        typer.Option(
            help="Specify service url to use in the returned manifest, instead of the external URL in the Virtual Machine export status. This is useful for NodePorts or if you don't have an external URL configured"
        ),
    ] = None,
    insecure: Annotated[
        bool,
        typer.Option(
            "--insecure",
            help="Specifies that the http request should be insecure.",
        ),
    ] = False,
    volume: Annotated[
        str | None, typer.Option(help="Specific volume name to download")
    ] = None,
    format: Annotated[
        VMImageFormat,
        typer.Option(
            help="Used to specify the format of the downloaded image. There's three options: gzip (default), raw and qcow2."
        ),
    ] = "gzip",
    sparsify: Annotated[
        bool,
        typer.Option(
            "--sparsify", help="If converting to qcow2, sparsify using virt-sparsify"
        ),
    ] = False,
    manifest: Annotated[
        bool,
        typer.Option(
            "--manifest",
            help="Instead of downloading a volume, retrieve the VM manifest",
        ),
    ] = False,
    manifest_output_format: Annotated[
        ManifestFormat,
        typer.Option(
            help="Manifest output format, defaults to Yaml. Valid options are yaml or json"
        ),
    ] = "yaml",
    port_forward: Annotated[
        bool,
        typer.Option(
            "--port-forward",
            help="Configures port-forwarding on a random port. Useful to download without proper ingress/route configuration.",
        ),
    ] = False,
    local_port: Annotated[
        int, typer.Option(help="Defines the specific port to be used in port-forward.")
    ] = 0,
    retry: Annotated[
        int,
        typer.Option(
            help="When export server returns a transient error, we retry this number of times before giving up"
        ),
    ] = 0,
    include_secret: Annotated[
        bool,
        typer.Option(
            "--include-secret",
            help="When used with manifest and set to true include a secret that contains proper headers for CDI to import using the manifest",
        ),
    ] = False,
):
    console = Console()
    if delete_vme and keep_vme:
        raise typer.BadParameter("Cannot specify both --delete-vme and --keep-vme")

    if not manifest and not output:
        raise typer.BadParameter(
            "binary output can mess up your terminal. Use '--output <FILE>' when downloading a volume."
        )

    if pvc and manifest:
        raise typer.BadParameter("cannot get manifest for PVC export")

    async with dynamic_client() as dyn:
        k8s_conf = client.Configuration.get_default_copy()

        kv_conf = Configuration()
        kv_conf.host = k8s_conf.host
        kv_conf.verify_ssl = getattr(k8s_conf, "verify_ssl", True)
        kv_conf.ssl_ca_cert = getattr(k8s_conf, "ssl_ca_cert", None)

        kv_api_client = ApiClient(configuration=kv_conf)

        if k8s_conf.api_key:
            token = k8s_conf.api_key.get("BearerToken")

            if token:
                kv_api_client.default_headers["Authorization"] = token

        kv_api = DefaultApi(kv_api_client)

        vme_info = VMExportInfo(
            name=name,
            namespace=namespace,
            service_url=service_url,
            manifest_output_format=manifest_output_format,
            volume=volume,
            decompress=(format in ("raw", "qcow2")),
            should_create=bool(vm) or bool(snapshot) or bool(pvc),
            format=format,
            insecure=insecure,
            delete_vme=delete_vme,
            keep_vme=keep_vme,
            port_forward=port_forward,
            local_port=local_port,
            sparsify=sparsify,
            output_file=output,
            ttl=ttl,
            readiness_timeout=readiness_timeout,
            download_retries=retry,
            labels=convert_list_to_dict(labels),
            annotations=convert_list_to_dict(annotations),
            export_source=get_export_source(vm, snapshot, pvc),
            export_manifest=manifest,
            include_secret=include_secret,
        )

        if vme_info.should_create:
            try:
                console.print(f"[yellow]Creating VMExport resource...[/yellow]")
                await create_export_resource(kv_api, vme_info)
            except VMExportAlreadyExistsError as e:
                vme_info.keep_vme = True
                console.print(e)

        try:
            await wait_for_export_ready(kv_api, vme_info, console)
        except TimeoutError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1)

        if port_forward:
            vme_info.insecure = True
            vme_info.service_url = f"127.0.0.1:{local_port}"
            pf = await setup_port_forward(
                dyn,
                vme_info,
            )
            console.print(f"forwarding on 127.0.0.1:{pf.local_port}")

        if not (vme := await get_virtual_machine_export(kv_api, vme_info)):
            console.print(
                f"unable to get {vme_info.namespace}/{vme_info.name} VirtualMachineExport"
            )
            raise typer.Exit(1)

        if manifest:
            await get_virtual_machine_manifest(dyn, vme, vme_info)
            raise typer.Exit(0)

        output_path = cast(Path, vme_info.output_file)
        if vme_info.format == "qcow2":
            download_dest = output_path.with_suffix(output_path.suffix + ".raw")

            await download_volume(dyn, vme, vme_info, console, dest_path=download_dest)

            if convert_to_qcow2(download_dest, output_path, console, vme_info.sparsify):
                console.print(
                    f"[green]✓ QCOW2 conversion finished successfully: {output_path}[/green]"
                )
                try:
                    download_dest.unlink(missing_ok=True)
                    console.print(
                        f"[dim]✓ Cleaned up source raw image after conversion: {download_dest}[/dim]"
                    )
                except Exception as e:
                    console.print(
                        f"[yellow]Warning: Could not delete source raw image file after conversion: {download_dest}: {e}[/yellow]"
                    )
            else:
                console.print(
                    f"[red]! Error: QCOW2 conversion failed. Raw file kept at: {download_dest}[/red]"
                )
                raise typer.Exit(1)
        else:
            await download_volume(dyn, vme, vme_info, console, dest_path=output_path)
            console.print(
                f"[green]✓ {output_path} (format: {vme_info.format.upper()}) downloaded successfully.[/green]"
            )

        if should_delete_vmexport(vme_info):
            console.print("[dim]Deleting VMExport resource...[/dim]")
            try:
                await asyncio.to_thread(
                    kv_api.delete_namespaced_virtual_machine_export,
                    name,
                    namespace,
                    body=K8sIoApimachineryPkgApisMetaV1DeleteOptions(),
                )
            except Exception as e:
                console.print(
                    f"[yellow]Warning: Failed to delete VMExport resource: {e}[/yellow]"
                )
