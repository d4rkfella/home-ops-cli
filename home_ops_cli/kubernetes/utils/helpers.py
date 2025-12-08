from pathlib import Path
import subprocess
from ruamel.yaml import YAML, YAMLError

def load_manifest(file: Path, decrypt: bool = False) -> list[dict]:
    if decrypt:
        sops_cmd = ["sops", "-d", str(file)]
        try:
            decrypted = subprocess.check_output(
                sops_cmd,
                env=os.environ,
                text=True,
                stderr=subprocess.PIPE,
            )
            docs = yaml.load_all(decrypted)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"SOPS decryption failed: {e.stderr}") from e
    else:
        with open(file, "r", encoding="utf-8") as f:
            docs = list(yaml.load_all(f))
    return docs
