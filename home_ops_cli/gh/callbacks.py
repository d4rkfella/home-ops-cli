import typer
import re

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
