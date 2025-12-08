from pathlib import Path

import aiohttp
import typer
from ruamel.yaml import YAML
from typing_extensions import Annotated

from ..utils import async_command

app = typer.Typer()


@app.command(help="Fetch AWS IP ranges and optionally update a network policy YAML")
@async_command
async def fetch_aws_ips(
    region: Annotated[str, typer.Option(help="AWS region to filter")] = "us-east-1",
    service: Annotated[str, typer.Option(help="AWS service to filter")] = "AMAZON",
    output_file: Annotated[
        Path, typer.Option(help="File to write filtered CIDRs")
    ] = Path("aws-ip-ranges.txt"),
    policy_file: Annotated[
        Path | None,
        typer.Option(
            help="Path to cilium network policy YAML to update",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            writable=True,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    yaml = YAML()
    yaml.preserve_quotes = True
    typer.echo(f"Fetching IP ranges for region='{region}' and service='{service}'...")

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://ip-ranges.amazonaws.com/ip-ranges.json"
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()

    cidrs = sorted(
        {
            prefix["ip_prefix"]
            for prefix in data["prefixes"]
            if prefix["region"] == region and prefix["service"] == service
        }
    )

    if not cidrs:
        typer.echo("No CIDRs found for the specified region and service.")
        raise typer.Exit()

    typer.echo(f"Found {len(cidrs)} unique CIDR blocks.")

    if policy_file:
        try:
            with open(policy_file, "r") as f:
                policy = yaml.load(f)

            target_port = "443"
            rule_to_update = None
            egress_rules = policy.get("spec", {}).get("egress")

            if isinstance(egress_rules, list):
                for rule in egress_rules:
                    if isinstance(rule.get("toPorts"), list):
                        for port_config in rule["toPorts"]:
                            if isinstance(port_config.get("ports"), list):
                                for port_entry in port_config["ports"]:
                                    if (
                                        isinstance(port_entry.get("port"), str)
                                        and port_entry["port"] == target_port
                                    ):
                                        rule_to_update = rule
                                        break
                                if rule_to_update:
                                    break
                        if rule_to_update:
                            break

            if rule_to_update is None:
                typer.echo(
                    f"[bold red]Error: Could not find an egress rule in {policy_file} targeting port '{target_port}'. Aborting policy update.[/bold red]",
                    err=True,
                )
                raise typer.Exit(code=1)

            egress_cidrs_list = rule_to_update.get("toCIDRSet", [])
            existing_cidrs = {
                entry["cidr"]
                for entry in egress_cidrs_list
                if isinstance(entry, dict) and "cidr" in entry
            }

            all_cidrs = sorted(existing_cidrs | set(cidrs))

            rule_to_update["toCIDRSet"] = [{"cidr": c} for c in all_cidrs]

            with open(policy_file, "w") as f:
                yaml.dump(policy, f)

            typer.echo(
                f"Updated {policy_file} with {
                    len(all_cidrs)
                } unique CIDRs in the egress rule targeting port {target_port}."
            )

        except Exception as e:
            typer.echo(
                f"[bold red]An error occurred during policy file processing: {e}[/bold red]",
                err=True,
            )
            raise typer.Exit(code=1)

    else:
        with open(output_file, "w") as f:
            for c in cidrs:
                f.write(f"- cidr: {c}\n")

        typer.echo(f"Wrote {len(cidrs)} CIDRs to {output_file}.")
