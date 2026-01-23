import base64
import shutil
import subprocess
import tempfile
from pathlib import Path

from typer import Argument, Exit, Option, Typer, echo
from typing_extensions import Annotated

app = Typer()


@app.command(
    help="Creates new talosconfig with key pair using the root Talos API CA from the control plane machine configuration."
)
def regen_talosconfig(
    controlplane: Annotated[
        Path,
        Argument(
            help="Path to control plane machine configuration",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    endpoints: Annotated[
        list[str] | None,
        Option("--endpoints", "-e", help="control plane endpoints"),
    ] = None,
    nodes: Annotated[
        list[str] | None, Option("--nodes", "-n", help="nodes endpoints")
    ] = None,
    context: Annotated[
        str, Option(help="context name to use for the new talosconfig")
    ] = "default",
    debug: Annotated[bool, Option(help="enable debugging", is_flag=True)] = False,
    decrypt: Annotated[
        bool,
        Option(help="decrypt the machine configuration with SOPS", is_flag=True),
    ] = True,
    output: Annotated[
        Path,
        Option(
            "--output",
            "-o",
            file_okay=True,
            dir_okay=False,
            writable=True,
            resolve_path=True,
            help="output path for the new talosconfig",
        ),
    ] = Path("talosconfig"),
):
    from ruamel.yaml import YAML

    yaml = YAML()

    work_dir = Path(tempfile.mkdtemp(prefix="talos-regen-"))
    echo(f"🔧 Working directory: {work_dir}")

    try:
        if not decrypt:
            content = controlplane.read_text()
        else:
            content = subprocess.run(
                ["sops", "-d", str(controlplane)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout

        ca_crt_b64 = None
        ca_key_b64 = None
        for doc in yaml.load_all(content):
            if doc and "machine" in doc and "ca" in doc.get("machine", {}):
                ca_crt_b64 = doc["machine"]["ca"]["crt"]
                ca_key_b64 = doc["machine"]["ca"]["key"]
                break

        if not ca_crt_b64 or not ca_key_b64:
            echo(
                "Could not find machine.ca.crt or machine.ca.key in controlplane machine configuration",
                err=True,
            )
            raise Exit(code=1)

        ca_crt_path = work_dir / "ca.crt"
        ca_key_path = work_dir / "ca.key"
        ca_crt_path.write_bytes(base64.b64decode(ca_crt_b64))
        ca_key_path.write_bytes(base64.b64decode(ca_key_b64))
        echo("✅ Extracted CA certificate and key")

        subprocess.run(
            ["talosctl", "gen", "key", "--name", "admin"], cwd=work_dir, check=True
        )
        subprocess.run(
            ["talosctl", "gen", "csr", "--key", "admin.key", "--ip", "127.0.0.1"],
            cwd=work_dir,
            check=True,
        )
        subprocess.run(
            [
                "talosctl",
                "gen",
                "crt",
                "--ca",
                "ca",
                "--csr",
                "admin.csr",
                "--name",
                "admin",
                "--hours",
                "8760",
            ],
            cwd=work_dir,
            check=True,
        )
        echo("✅ Generated admin key, CSR, and certificate")

        admin_crt_path = work_dir / "admin.crt"
        admin_key_path = work_dir / "admin.key"

        config = {
            "context": context,
            "contexts": {
                context: {
                    "endpoints": endpoints or [],
                    "nodes": nodes or [],
                    "ca": base64.b64encode(ca_crt_path.read_bytes()).decode("utf-8"),
                    "crt": base64.b64encode(admin_crt_path.read_bytes()).decode(
                        "utf-8"
                    ),
                    "key": base64.b64encode(admin_key_path.read_bytes()).decode(
                        "utf-8"
                    ),
                }
            },
        }

        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as f:
            yaml.dump(config, f)
        echo(f"✅ Created talosconfig: {output}")

    finally:
        if not debug:
            shutil.rmtree(work_dir)
            echo("🧹 Cleaned up temporary files")
        else:
            echo(f"📁 Temporary files kept in: {work_dir}")
