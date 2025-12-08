import typer
import re


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
