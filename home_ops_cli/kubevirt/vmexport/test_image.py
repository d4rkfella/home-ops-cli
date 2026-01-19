import asyncio
import json
import os
import sys
import time
from asyncio import StreamReader, StreamWriter
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ...utils import async_command, find_free_port

app = typer.Typer(
    help="Test VM image locally with qemu for integrity errors and guest agent responsiveness"
)


async def qemu_image_check(image_path: Path, console: Console) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "qemu-img",
            "check",
            str(image_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        output = stdout.decode() + stderr.decode()

        if proc.returncode == 0:
            console.print("[green]✓ QEMU image check passed[/green]")
            if output:
                console.print(f"[dim]{output.strip()}[/dim]")
            return True
        else:
            console.print(f"[red]✗ QEMU image check failed[/red]")
            console.print(f"[red]{output}[/red]")
            return False
    except FileNotFoundError:
        console.print("[red]Error: qemu-img not found in system PATH.[/red]")
        raise typer.Exit(1)


async def get_image_info(image_path: Path, console: Console) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "qemu-img",
            "info",
            "--output=json",
            str(image_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            return json.loads(stdout.decode())
        else:
            console.print(
                f"[red]Error: Failed to get image info: {stderr.decode()}[/red]"
            )
            return {}
    except FileNotFoundError:
        console.print("[red]Error: qemu-img not found in system PATH[/red]")
        return {}


async def spawn_vm_process(
    image_path: Path, qmp_port: int, memory: str, cpus: int, console: Console
) -> asyncio.subprocess.Process | None:
    machine = (
        "type=q35,accel=kvm" if Path("/dev/kvm").exists() else "type=q35,accel=tcg"
    )
    qemu_cmd = [
        "qemu-system-x86_64",
        "-machine",
        machine,
        "-m",
        memory,
        "-smp",
        str(cpus),
        "-drive",
        f"file={image_path},if=virtio,snapshot=on",
        "-net",
        "none",
        "-qmp",
        f"tcp:127.0.0.1:{qmp_port},server,wait=off",
        "-device",
        "virtio-serial",
        "-chardev",
        f"socket,path=/tmp/qga-{qmp_port}.sock,server=on,wait=off,id=qga0",
        "-device",
        "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        "-display",
        "vnc=127.0.0.1:0",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *qemu_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        console.print(f"[green]QEMU process started (PID: {proc.pid}) [/green]")
        console.print(
            f"[dim]QEMU Monitor Protocol configured on port: {qmp_port}[/dim]"
        )

        await asyncio.sleep(2)

        if proc.returncode is not None:
            _, stderr = await proc.communicate()
            console.print(
                f"[red]Error: QEMU process has exited prematurely with status {proc.returncode}: {stderr.decode().strip()}[/red]"
            )
            return None

        return proc

    except FileNotFoundError:
        console.print("[red]Error: qemu-system-x86_64 not found in system PATH.[/red]")
        raise typer.Exit(1)


class QMPClient:
    def __init__(self, host: str, port: int, console: Console):
        self.host = host
        self.port = port
        self.console = console
        self.reader: StreamReader | None = None
        self.writer: StreamWriter | None = None

    async def connect(self, timeout: int = 2) -> bool:
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=timeout
            )

            _ = await self.reader.readline()
            await self.execute("qmp_capabilities")
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def execute(
        self, command: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self.reader is None or self.writer is None:
            raise RuntimeError("QMPClient is not connected")

        cmd: dict[str, Any] = {"execute": command}
        if arguments is not None:
            cmd["arguments"] = arguments

        self.writer.write(json.dumps(cmd).encode() + b"\n")
        await self.writer.drain()

        response_bytes = await self.reader.readline()
        response_str = response_bytes.decode()
        return json.loads(response_str)

    def close(self):
        if self.writer:
            self.writer.close()


async def qmp_healthcheck(qmp_port: int, console: Console) -> bool:
    console.print(f"[yellow]Running QMP healthcheck...[/yellow]")
    timeout = 30
    start = time.time()
    qmp_client: QMPClient | None = None
    healthcheck_status = f"Attempting connection on 127.0.0.1:{qmp_port} ..."

    is_ci = os.getenv("GITHUB_ACTIONS") == "true" or not console.is_terminal

    with Progress(
        SpinnerColumn() if not is_ci else TextColumn("•"),
        TextColumn("[dim]{task.fields[msg]}"),
        console=console,
        transient=False,
        auto_refresh=not is_ci,
    ) as progress:
        task = progress.add_task(
            "healthcheck",
            msg=f"QMP healthcheck in progress. State: [red]{healthcheck_status}[/red]",
            total=None,
        )

        last_refresh = 0.0

        while True:
            elapsed = int(time.time() - start)

            if elapsed >= timeout:
                break

            try:
                if qmp_client is None:
                    qmp_client = QMPClient("127.0.0.1", qmp_port, console)
                    if not await qmp_client.connect(timeout=2):
                        healthcheck_status = "Waiting for QMP to become available"
                        qmp_client = None

                        progress.update(
                            task,
                            msg=f"[{elapsed}s]QMP Healthcheck in progress. State: [red]{healthcheck_status}[/red]",
                        )
                        if is_ci:
                            if time.time() - last_refresh >= 5.0:
                                progress.refresh()
                                last_refresh = time.time()

                        await asyncio.sleep(1)
                        continue

                status_res = await qmp_client.execute("query-status")
                vm_status = status_res.get("return", {}).get("status")

                if vm_status == "running":
                    block_res = await qmp_client.execute("query-block")
                    devices = block_res.get("return", [])

                    if any(
                        d.get("inserted", {}).get("io-status") == "failed"
                        for d in devices
                    ):
                        healthcheck_status = "Disk I/O error"
                    else:
                        progress.update(
                            task,
                            msg=f"[green][{elapsed}s]✓ QMP healthy, VM running[/green]",
                        )
                        if is_ci:
                            progress.refresh()
                        qmp_client.close()
                        return True
                else:
                    healthcheck_status = f"VM not running (Status: {vm_status})"

            except Exception as e:
                healthcheck_status = f"Waiting ({type(e).__name__})"
                if qmp_client:
                    qmp_client.close()
                    qmp_client = None

            progress.update(
                task,
                msg=f"[{elapsed}s]QMP Healthcheck in progress. State: [red]{healthcheck_status}[/red]",
            )

            if is_ci:
                if time.time() - last_refresh >= 5.0:
                    progress.refresh()
                    last_refresh = time.time()

            await asyncio.sleep(1)

        progress.update(
            task,
            msg=f"[red]Error: QMP Healthcheck failed after {timeout}s: {healthcheck_status}[/red]",
        )
        if is_ci:
            progress.refresh()

        if qmp_client:
            qmp_client.close()

        return False


async def guest_agent_healthcheck(
    qmp_port: int, timeout: int, console: Console
) -> bool:
    console.print(f"[yellow]Running guest agent healthcheck...[/yellow]")
    qga_socket = f"/tmp/qga-{qmp_port}.sock"
    is_ci = os.getenv("GITHUB_ACTIONS") == "true" or not console.is_terminal

    with Progress(
        SpinnerColumn() if not is_ci else TextColumn("•"),
        TextColumn("[dim]{task.fields[msg]}"),
        console=console,
        transient=False,
        auto_refresh=not is_ci,
    ) as progress:
        task = progress.add_task("wait", msg="Waiting for guest agent...", total=None)
        start = time.time()
        last_refresh = 0.0

        while time.time() - start < timeout:
            if Path(qga_socket).exists():
                try:
                    async with asyncio.timeout(5):
                        reader, writer = await asyncio.open_unix_connection(qga_socket)
                        writer.write(
                            json.dumps({"execute": "guest-ping"}).encode() + b"\n"
                        )
                        await writer.drain()
                        resp = await reader.readline()
                        writer.close()
                        await writer.wait_closed()

                        if b"return" in resp:
                            progress.update(
                                task, msg="[green]✓ Guest agent is responsive[/green]"
                            )
                            if is_ci:
                                progress.refresh()

                            async with asyncio.timeout(5):
                                reader, writer = await asyncio.open_unix_connection(
                                    qga_socket
                                )
                                writer.write(
                                    json.dumps({"execute": "guest-info"}).encode()
                                    + b"\n"
                                )
                                await writer.drain()
                                info_resp = await reader.readline()
                                writer.close()
                                await writer.wait_closed()

                                info = json.loads(info_resp.decode()).get("return", {})
                                if info:
                                    console.print(
                                        f"[green]  Guest agent version: {info.get('version', 'unknown')}[/green]"
                                    )

                            return True
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

            elapsed = int(time.time() - start)
            progress.update(task, msg=f"Waiting for guest agent... ({elapsed}s)")

            if is_ci and (time.time() - last_refresh >= 5.0):
                progress.refresh()
                last_refresh = time.time()

            await asyncio.sleep(3)

        progress.update(
            task, msg=f"[red]Error: Guest agent did not respond within {timeout}s[/red]"
        )
        if is_ci:
            progress.refresh()
        return False


async def shutdown_vm(
    proc: asyncio.subprocess.Process,
    qmp_port: int,
    console: Console,
    agent_ok: bool = False,
):
    console.print("[yellow]Shutting down VM...[/yellow]")

    shutdown_attempted = False

    if agent_ok:
        qga_socket = f"/tmp/qga-{qmp_port}.sock"
        if Path(qga_socket).exists():
            console.print(
                "[dim]Attempting guest-shutdown command via QEMU Guest Agent...[/dim]"
            )
            try:
                _, writer = await asyncio.open_unix_connection(qga_socket)
                writer.write(json.dumps({"execute": "guest-shutdown"}).encode() + b"\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                shutdown_attempted = True
            except Exception as e:
                console.print(
                    f"[yellow]Error: Sending guest agent shutdown command failed: {e}[/yellow]"
                )

    if not shutdown_attempted:
        try:
            qmp = QMPClient("127.0.0.1", qmp_port, console)
            if await qmp.connect(timeout=5):
                console.print(
                    "[dim]Attempting ACPI system_powerdown command via QEMU Monitor Protocol...[/dim]"
                )
                try:
                    await qmp.execute("system_powerdown")
                    shutdown_attempted = True
                except Exception as e:
                    console.print(
                        f"[yellow]Error: Sending ACPI shutdown command failed: {e}[/yellow]"
                    )
            qmp.close()
        except Exception as e:
            console.print(
                f"[yellow]QMP connection failed during shutdown: {e}[/yellow]"
            )

    if shutdown_attempted:
        await asyncio.sleep(10)
        start = time.time()
        timeout = 60
        while time.time() - start < timeout:
            if proc.returncode is not None:
                console.print("[green]✓ VM shut down gracefully[/green]")
                return
            await asyncio.sleep(1)
        console.print(
            f"[yellow]VM did not shutdown gracefuly after {timeout}s, killing qemu process...[/yellow]"
        )

    proc.kill()
    await proc.wait()
    console.print("[green]✓ VM process terminated[/green]")


@app.command()
@async_command
async def test_image(
    image: Annotated[Path, typer.Argument(help="Path to VM image file to test")],
    memory: Annotated[str, typer.Option(help="Memory for test VM")] = "2G",
    cpus: Annotated[int, typer.Option(help="Number of CPUs for test VM")] = 2,
    agent_timeout: Annotated[
        int,
        typer.Option(help="Timeout in seconds for guest agent responsiveness check."),
    ] = 300,
):
    console = Console()
    if not image.exists():
        console.print(f"[red]Error: Image file not found: {image}[/red]")
        raise typer.Exit(1)

    console.print(
        f"[bold blue]Starting VM Image Validation for file {image.name}[/bold blue]\n"
    )

    with console.status("[bold yellow]Running QEMU image check...[/bold yellow]"):
        if not await qemu_image_check(image, console):
            raise typer.Exit(1)

    with console.status("[bold yellow]Image info:[/bold yellow]"):
        info = await get_image_info(image, console)
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_row("Format:", f"[green]{info.get('format', 'unknown')}[/green]")
        table.add_row(
            "Virtual Size:",
            f"[green]{info.get('virtual-size', 0) / (1024**3):.2f} GB[/green]",
        )
        table.add_row(
            "Actual Size:",
            f"[green]{info.get('actual-size', 0) / (1024**3):.2f} GB[/green]",
        )
        console.print(table)

    qmp_port = find_free_port()
    proc = None
    agent_ok = False

    try:
        proc = await spawn_vm_process(image, qmp_port, memory, cpus, console)
        if not proc:
            raise typer.Exit(1)

        if not await qmp_healthcheck(qmp_port, console):
            if proc and proc.returncode is not None:
                _, stderr = await proc.communicate()
                if stderr:
                    console.print(
                        f"Error: QEMU process exited with an error: [bold red]{stderr.decode()}[/bold red]"
                    )
            raise typer.Exit(1)

        if not (
            agent_ok := await guest_agent_healthcheck(qmp_port, agent_timeout, console)
        ):
            raise typer.Exit(1)
    finally:
        if proc:
            await shutdown_vm(proc, qmp_port, console, agent_ok)

        qga_socket = f"/tmp/qga-{qmp_port}.sock"
        if os.path.exists(qga_socket):
            os.remove(qga_socket)
        if sys.stdin.isatty():
            os.system("stty sane")
