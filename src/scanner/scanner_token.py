# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #

import os

from rich.console import Console
from rich.prompt import Prompt

console = Console()


def prompt_github_token() -> None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and token.strip():
        return

    console.print("[bold yellow][!] No GITHUB_TOKEN found. Unauthenticated requests are rate-limited to 60/hour.[/]")
    console.print("[dim]    Generate a free token at: https://github.com/settings/tokens (no scopes needed)[/]")
    entered = Prompt.ask(
        "[bold cyan]Enter your GitHub token (or press Enter to skip)[/]",
        password=True,
        default="",
    )

    if entered:
        os.environ["GITHUB_TOKEN"] = entered
        console.print("[bold green]    [+] GitHub token set for this session.[/]\n")
    else:
        console.print("[bold yellow]    [!] Skipping — expect rate limiting.[/]\n")
