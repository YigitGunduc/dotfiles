#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import importlib
import json
import sys
import time
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import quote

try:
    keyring = importlib.import_module("keyring")
    keyring_errors = importlib.import_module("keyring.errors")
    pyotp = importlib.import_module("pyotp")
    rich_console = importlib.import_module("rich.console")
    rich_live = importlib.import_module("rich.live")
    rich_panel = importlib.import_module("rich.panel")
    rich_prompt = importlib.import_module("rich.prompt")
    rich_table = importlib.import_module("rich.table")
except ModuleNotFoundError:
    keyring = None
    keyring_errors = None
    pyotp = None
    rich_console = None
    rich_live = None
    rich_panel = None
    rich_prompt = None
    rich_table = None

APP_NAME = "luminum-auth"
INDEX_ACCOUNT = "__services__"
ACCENT = "bold cyan"
SUCCESS = "bold green"
WARNING = "bold yellow"
ERROR = "bold red"

Console = rich_console.Console if rich_console else None
Live = rich_live.Live if rich_live else None
Panel = rich_panel.Panel if rich_panel else None
Prompt = rich_prompt.Prompt if rich_prompt else None
Confirm = rich_prompt.Confirm if rich_prompt else None
Table = rich_table.Table if rich_table else None
KeyringError = keyring_errors.KeyringError if keyring_errors else Exception
PasswordDeleteError = keyring_errors.PasswordDeleteError if keyring_errors else Exception

console = Console() if Console else None


class AuthError(Exception):
    """Raised for user-facing authenticator failures."""


@dataclass(frozen=True)
class SecretRecord:
    service: str
    secret: str
    issuer: str | None = None
    digits: int = 6
    interval: int = 30

    @property
    def label(self) -> str:
        return self.issuer or self.service

    def to_payload(self) -> str:
        return json.dumps(
            {
                "service": self.service,
                "secret": self.secret,
                "issuer": self.issuer,
                "digits": self.digits,
                "interval": self.interval,
            }
        )

    @classmethod
    def from_payload(cls, payload: str, default_service: str) -> "SecretRecord":
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            # Backward compatibility for legacy plain-secret records.
            return cls(service=default_service, secret=normalize_secret(payload))

        secret = normalize_secret(data["secret"])
        service = data.get("service") or default_service
        issuer = data.get("issuer")
        digits = int(data.get("digits", 6))
        interval = int(data.get("interval", 30))
        validate_secret(secret, digits=digits, interval=interval)
        return cls(
            service=service,
            secret=secret,
            issuer=issuer,
            digits=digits,
            interval=interval,
        )


def current_user() -> str:
    return getpass.getuser()


def ensure_dependencies() -> None:
    missing = []
    if keyring is None:
        missing.append("keyring")
    if pyotp is None:
        missing.append("pyotp")
    if Console is None or Live is None or Panel is None or Prompt is None or Confirm is None or Table is None:
        missing.append("rich")

    if missing:
        missing_csv = ", ".join(missing)
        raise AuthError(
            f"Missing Python dependencies: {missing_csv}. Install them with "
            f"`./install.sh` from the dotfiles root, or install them inside a virtualenv."
        )


def normalize_service(service: str) -> str:
    value = service.strip().lower()
    if not value:
        raise AuthError("Service name cannot be empty.")
    return value


def normalize_secret(secret: str) -> str:
    value = secret.strip().replace(" ", "")
    if not value:
        raise AuthError("Secret cannot be empty.")
    return value


def validate_secret(secret: str, digits: int = 6, interval: int = 30) -> None:
    try:
        pyotp.TOTP(secret, digits=digits, interval=interval).now()
    except Exception as exc:
        raise AuthError("Invalid TOTP secret or unsupported OTP configuration.") from exc


def account_name(service: str, username: str | None = None) -> str:
    user = username or current_user()
    return f"{user}:{normalize_service(service)}"


def keyring_get(service: str, username: str | None = None) -> str | None:
    normalized = normalize_service(service)
    user_account = account_name(normalized, username)
    try:
        payload = keyring.get_password(APP_NAME, user_account)
        if payload:
            return payload
        # Backward compatibility for old non-user-scoped entries.
        return keyring.get_password(APP_NAME, normalized)
    except KeyringError as exc:
        raise AuthError(f"Unable to read from macOS Keychain: {exc}") from exc


def keyring_set(service: str, payload: str, username: str | None = None) -> None:
    try:
        keyring.set_password(APP_NAME, account_name(service, username), payload)
    except KeyringError as exc:
        raise AuthError(f"Unable to write to macOS Keychain: {exc}") from exc


def keyring_delete(service: str, username: str | None = None) -> None:
    target = account_name(service, username)
    try:
        try:
            keyring.delete_password(APP_NAME, target)
        except PasswordDeleteError:
            # Best-effort cleanup for legacy records.
            keyring.delete_password(APP_NAME, normalize_service(service))
    except KeyringError as exc:
        raise AuthError(f"Unable to delete Keychain item: {exc}") from exc


def load_index(username: str | None = None) -> list[str]:
    user = username or current_user()
    try:
        payload = keyring.get_password(APP_NAME, f"{INDEX_ACCOUNT}:{user}")
    except KeyringError as exc:
        raise AuthError(f"Unable to read service index from Keychain: {exc}") from exc

    if not payload:
        return []

    try:
        services = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise AuthError("Stored service index is corrupted.") from exc

    if not isinstance(services, list):
        raise AuthError("Stored service index is corrupted.")

    return sorted({normalize_service(item) for item in services})


def save_index(services: Iterable[str], username: str | None = None) -> None:
    user = username or current_user()
    payload = json.dumps(sorted({normalize_service(item) for item in services}))
    try:
        keyring.set_password(APP_NAME, f"{INDEX_ACCOUNT}:{user}", payload)
    except KeyringError as exc:
        raise AuthError(f"Unable to update service index in Keychain: {exc}") from exc


def upsert_index(service: str, username: str | None = None) -> None:
    services = load_index(username)
    services.append(service)
    save_index(services, username)


def remove_from_index(service: str, username: str | None = None) -> None:
    normalized = normalize_service(service)
    services = [item for item in load_index(username) if item != normalized]
    save_index(services, username)


def parse_secret_input(raw_secret: str, fallback_service: str) -> SecretRecord:
    candidate = raw_secret.strip()
    if candidate.lower().startswith("otpauth://"):
        try:
            otp = pyotp.parse_uri(candidate)
        except Exception as exc:
            raise AuthError("Invalid otpauth URI.") from exc

        if not isinstance(otp, pyotp.TOTP):
            raise AuthError("Only TOTP secrets are supported.")

        secret = normalize_secret(otp.secret)
        service = normalize_service(getattr(otp, "name", None) or fallback_service)
        issuer = getattr(otp, "issuer", None) or None
        digits = int(getattr(otp, "digits", 6))
        interval = int(getattr(otp, "interval", 30))
        validate_secret(secret, digits=digits, interval=interval)
        return SecretRecord(
            service=service,
            secret=secret,
            issuer=issuer,
            digits=digits,
            interval=interval,
        )

    secret = normalize_secret(candidate)
    validate_secret(secret)
    return SecretRecord(service=normalize_service(fallback_service), secret=secret)


def build_totp(record: SecretRecord) -> pyotp.TOTP:
    return pyotp.TOTP(record.secret, digits=record.digits, interval=record.interval)


def seconds_remaining(interval: int) -> int:
    remaining = interval - (int(time.time()) % interval)
    return interval if remaining == 0 else remaining


def record_uri(record: SecretRecord, username: str | None = None) -> str:
    user = username or current_user()
    label = quote(f"{record.label}:{user}")
    params = [f"secret={record.secret}"]
    if record.issuer:
        params.append(f"issuer={quote(record.issuer)}")
    if record.digits != 6:
        params.append(f"digits={record.digits}")
    if record.interval != 30:
        params.append(f"period={record.interval}")
    return f"otpauth://totp/{label}?{'&'.join(params)}"


def load_record(service: str, username: str | None = None) -> SecretRecord:
    payload = keyring_get(service, username)
    if not payload:
        raise AuthError(f"No secret found for '{service}' under macOS user '{username or current_user()}'.")
    return SecretRecord.from_payload(payload, default_service=normalize_service(service))


def store_secret_interactive(service: str | None = None) -> int:
    console.print(Panel("[bold]Add New TOTP Service[/bold]", border_style="cyan"))
    default_service = service or ""
    service_name = Prompt.ask("[bold white]Service Name[/bold white]", default=default_service).strip()
    raw_secret = Prompt.ask(
        "[bold white]Secret or otpauth URI[/bold white]",
        password=True,
    )
    record = parse_secret_input(raw_secret, fallback_service=service_name)

    if keyring_get(record.service):
        overwrite = Confirm.ask(
            f"[{WARNING}]'{record.service}' already exists for macOS user '{current_user()}'. Overwrite?[/]"
        )
        if not overwrite:
            console.print(f"[{WARNING}]Cancelled.[/]")
            return 1

    keyring_set(record.service, record.to_payload())
    upsert_index(record.service)
    console.print(
        f"[{SUCCESS}]Stored '{record.service}' for macOS user '{current_user()}' in Keychain.[/]"
    )
    return 0


def remove_service(service: str) -> int:
    load_record(service)
    if not Confirm.ask(
        f"[{WARNING}]Delete '{normalize_service(service)}' for macOS user '{current_user()}'?[/]"
    ):
        console.print(f"[{WARNING}]Cancelled.[/]")
        return 1

    keyring_delete(service)
    remove_from_index(service)
    console.print(f"[{SUCCESS}]Removed '{normalize_service(service)}'.[/]")
    return 0


def list_services() -> int:
    services = load_index()
    table = Table(title=f"{APP_NAME} services for {current_user()}", border_style="bright_black")
    table.add_column("Service", style=ACCENT)
    table.add_column("Status")

    if not services:
        console.print(f"[{WARNING}]No indexed services found for macOS user '{current_user()}'.[/]")
        return 0

    for service in services:
        try:
            record = load_record(service)
            status = f"[green]ready[/] ({record.digits} digits / {record.interval}s)"
        except AuthError:
            status = "[red]missing or invalid[/]"
        table.add_row(service, status)

    console.print(table)
    return 0


def show_code(service: str, once: bool = False, reveal_uri: bool = False) -> int:
    record = load_record(service)
    totp = build_totp(record)

    if reveal_uri:
        console.print(record_uri(record))
        return 0

    with Live(refresh_per_second=4, console=console) as live:
        while True:
            code = totp.now()
            remaining = seconds_remaining(record.interval)

            table = Table.grid(padding=1)
            table.add_column(style=ACCENT, justify="left")
            table.add_row(f"  {record.label.upper()}")
            table.add_row(f"  [bold white]{code[:3]} {code[3:]}[/]")

            width = 20
            filled = max(1, round((remaining / record.interval) * width))
            progress = f"[{'━' * filled}{' ' * (width - filled)}]"
            table.add_row(f"  [dim]{progress} {remaining}s[/]")
            table.add_row(f"  [dim]macOS user: {current_user()}[/]")

            live.update(Panel(table, border_style="bright_black", expand=False))
            if once:
                break
            time.sleep(0.25)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auther",
        description="Terminal TOTP authenticator backed by macOS Keychain.",
    )
    subparsers = parser.add_subparsers(dest="command")

    add_parser = subparsers.add_parser("add", help="Store a new TOTP secret.")
    add_parser.add_argument("service", nargs="?", help="Service name to store.")

    show_parser = subparsers.add_parser("show", help="Show a live TOTP code.")
    show_parser.add_argument("service", help="Service name to display.")
    show_parser.add_argument("--once", action="store_true", help="Print a single code frame and exit.")
    show_parser.add_argument(
        "--reveal-uri",
        action="store_true",
        help="Print the normalized otpauth URI for the stored record.",
    )

    remove_parser = subparsers.add_parser("remove", help="Delete a stored TOTP secret.")
    remove_parser.add_argument("service", help="Service name to remove.")

    subparsers.add_parser("list", help="List services stored for the current macOS user.")

    return parser


def compat_args(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if argv[0] == "--add":
        return ["add", *argv[1:]]
    if argv[0].startswith("-"):
        return argv
    return ["show", *argv]


def main(argv: list[str] | None = None) -> int:
    args_in = compat_args(argv if argv is not None else sys.argv[1:])
    parser = build_parser()
    args = parser.parse_args(args_in)

    ensure_dependencies()

    console.print(
        f"[dim]{APP_NAME}[/] [cyan]•[/] [dim]macOS user: {current_user()}[/]\n"
    )

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "add":
        return store_secret_interactive(args.service)
    if args.command == "show":
        return show_code(args.service, once=args.once, reveal_uri=args.reveal_uri)
    if args.command == "remove":
        return remove_service(args.service)
    if args.command == "list":
        return list_services()

    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        if console:
            console.print("\n[dim]Session closed.[/]")
        else:
            print("\nSession closed.")
        raise SystemExit(130)
    except AuthError as exc:
        if console:
            console.print(f"[{ERROR}]Error:[/] {exc}")
        else:
            print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
