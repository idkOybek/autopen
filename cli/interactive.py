"""Interactive mode for pentest-cli using prompt_toolkit."""

import sys
from typing import List, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion, WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console

console = Console()

# Command structure for auto-completion
COMMANDS = {
    "scan": {
        "start": ["--config", "--targets-file", "--targets", "--ftp-url", "--help"],
        "status": ["--follow", "--help"],
        "list": ["--status", "--limit", "--help"],
        "stop": ["--help"],
        "pause": ["--help"],
        "resume": ["--help"],
        "help": [],
    },
    "report": {
        "generate": ["--type", "--output", "--help"],
        "send": ["--telegram", "--email", "--ftp", "--help"],
        "help": [],
    },
    "system": {
        "status": ["--help"],
        "metrics": ["--help"],
        "help": [],
    },
    "config": {
        "show": ["--help"],
        "set": ["--help"],
        "help": [],
    },
    "help": [],
    "exit": [],
    "quit": [],
    "clear": [],
}


class PentestCompleter(Completer):
    """Custom completer for pentest-cli commands."""

    def get_completions(self, document, complete_event):
        """Generate completions based on current input.

        Args:
            document: Current document state.
            complete_event: Completion event.

        Yields:
            Completion objects for matching commands/options.
        """
        text = document.text_before_cursor
        words = text.split()

        if not words:
            # No input yet, suggest main commands
            for cmd in COMMANDS.keys():
                yield Completion(cmd, start_position=0)
            return

        # Get the last word being typed
        current_word = words[-1] if text.endswith(" ") else (words[-1] if words else "")
        word_before_cursor = document.get_word_before_cursor()

        if len(words) == 1 and not text.endswith(" "):
            # Completing main command
            for cmd in COMMANDS.keys():
                if cmd.startswith(current_word):
                    yield Completion(cmd, start_position=-len(word_before_cursor))

        elif len(words) >= 1:
            main_cmd = words[0]

            if main_cmd in COMMANDS:
                cmd_structure = COMMANDS[main_cmd]

                if isinstance(cmd_structure, dict):
                    # Has subcommands
                    if len(words) == 2 and not text.endswith(" "):
                        # Completing subcommand
                        for subcmd in cmd_structure.keys():
                            if subcmd.startswith(current_word):
                                yield Completion(subcmd, start_position=-len(word_before_cursor))

                    elif len(words) >= 2:
                        # Completing options for subcommand
                        subcmd = words[1]
                        if subcmd in cmd_structure:
                            options = cmd_structure[subcmd]
                            for option in options:
                                if option.startswith(current_word):
                                    yield Completion(option, start_position=-len(word_before_cursor))

                elif isinstance(cmd_structure, list):
                    # Main command with options only
                    for option in cmd_structure:
                        if option.startswith(current_word):
                            yield Completion(option, start_position=-len(word_before_cursor))


# Custom style for the prompt
prompt_style = Style.from_dict(
    {
        "prompt": "#00aa00 bold",
        "command": "#ffffff",
    }
)


def run_interactive_mode(cli_obj):
    """Run interactive REPL mode.

    Args:
        cli_obj: Click CLI object to execute commands.
    """
    from pathlib import Path

    # Setup history file
    history_file = Path.home() / ".pentest-cli-history"
    session = PromptSession(
        history=FileHistory(str(history_file)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=PentestCompleter(),
        style=prompt_style,
    )

    console.print("\n[bold green]Pentest CLI Interactive Mode[/bold green]")
    console.print("Type 'help' for available commands, 'exit' or 'quit' to leave.\n")

    while True:
        try:
            # Get user input
            user_input = session.prompt(
                [("class:prompt", "pentest> "), ("class:command", "")],
            ).strip()

            if not user_input:
                continue

            # Handle special commands
            if user_input.lower() in ["exit", "quit"]:
                console.print("[yellow]Goodbye![/yellow]")
                break

            if user_input.lower() == "clear":
                console.clear()
                continue

            # Parse command
            parts = user_input.split()
            command = parts[0]

            # Execute command through Click CLI
            try:
                # Import the CLI function
                from cli.main import cli

                # Prepare arguments
                args = parts[1:] if len(parts) > 1 else []

                # Execute the command
                ctx = cli.make_context("pentest-cli", [command] + args, obj={})
                cli.invoke(ctx)

            except SystemExit as e:
                # Click calls sys.exit(), catch it to continue the loop
                if e.code != 0:
                    console.print(f"[red]Command failed with exit code {e.code}[/red]")

            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

        except KeyboardInterrupt:
            # Ctrl+C pressed
            console.print("\n[yellow]Use 'exit' or 'quit' to leave[/yellow]")
            continue

        except EOFError:
            # Ctrl+D pressed
            console.print("\n[yellow]Goodbye![/yellow]")
            break

        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            continue


def add_interactive_command(cli):
    """Add interactive command to the CLI.

    Args:
        cli: Click CLI group to add the command to.
    """
    import click

    @cli.command("interactive")
    @click.pass_context
    def interactive_cmd(ctx):
        """Start interactive shell mode.

        Provides a REPL-like interface with:
        - Command history
        - Auto-completion
        - Auto-suggestions
        """
        run_interactive_mode(ctx.obj)

    return cli
