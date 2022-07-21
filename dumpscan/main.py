from pathlib import Path
from typing import List

import typer
from rich import inspect

from .common.output import get_dumpscan_console, get_dumpscan_table
from .common.scanners.symcrypt import SymcryptScanner
from .common.scanners.x509 import x509Scanner
from .kernel.renderers import RichRenderOption
from .kernel.vol import OS, Volatility
from .minidump.minidumpfile import MinidumpFile

app = typer.Typer(
    name="dumpscan", help="Scan memory dumps for secrets and keys", add_completion=False
)
kernel_app = typer.Typer()
minidump_app = typer.Typer()
app.add_typer(kernel_app, name="kernel", help="Scan kernel dump using volatility")
app.add_typer(minidump_app, name="minidump", help="Scan a user-mode minidump")
console = get_dumpscan_console()


def lowercase_list(value: List[str]) -> List[str]:
    """Callback function to make all strings in list lowercase"""
    return list(map(str.lower, value))


@kernel_app.command(
    name="envar", help="List process environment variables (Only for Windows)"
)
def kernel_envar(
    file: Path = typer.Option(..., "--file", "-f", help="Path to kernel dump"),
    pids: List[int] = typer.Option(
        [], "--pid", "-p", help="Pids to scan. Can be passed multiple times."
    ),
    render: RichRenderOption = typer.Option(
        RichRenderOption.TABLE,
        "--render",
        "-r",
        help="Render output (default: table)",
        case_sensitive=False,
        show_default=False,
    ),
):
    vol = Volatility(file, render, None)
    results = vol.run_envar(list(pids))
    console.print(results)


@kernel_app.command(
    name="cmdline", help="List command line for processes (Only for Windows)"
)
def kernel_cmdline(
    file: Path = typer.Option(..., "--file", "-f", help="Path to kernel dump"),
    pids: List[int] = typer.Option(
        [], "--pid", "-p", help="Pids to scan. Can be passed multiple times."
    ),
    render: RichRenderOption = typer.Option(
        RichRenderOption.TABLE,
        "--render",
        "-r",
        help="Render output (default: table)",
        case_sensitive=False,
        show_default=False,
    ),
):
    vol = Volatility(file, render, None)
    results = vol.run_cmdline(list(pids))
    console.print(results)


@kernel_app.command(
    name="pslist", help="List all the processes and their command line arguments"
)
def kernel_pslist(
    file: Path = typer.Option(..., "--file", "-f", help="Path to kernel dump"),
    os: OS = typer.Option(
        OS.WINDOWS,
        help="Operating system (default: windows)",
        case_sensitive=False,
        show_default=False,
    ),
    render: RichRenderOption = typer.Option(
        RichRenderOption.TABLE,
        "--render",
        "-r",
        help="Render output (default: table)",
        case_sensitive=False,
        show_default=False,
    ),
):
    vol = Volatility(file, render, None)
    results = vol.run_pslist(os)
    console.print(results)


@kernel_app.command(name="x509", help="Scan a kernel-mode dump for x509 certificates")
def kernel_x509(
    file: Path = typer.Option(
        ..., "--file", "-f", help="Path to kernel dump", dir_okay=False
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Path to dump objects to disk", file_okay=False
    ),
    pids: List[int] = typer.Option(
        [], "--pid", "-p", help="Pids to scan. Can be passed multiple times."
    ),
    procnames: List[str] = typer.Option(
        [],
        "--procname",
        "-n",
        help="Process names to scan. Can be passed multiple times.",
        callback=lowercase_list,
    ),
    render: RichRenderOption = typer.Option(
        RichRenderOption.TABLE,
        "--render",
        "-r",
        help="Render output (default: table)",
        case_sensitive=False,
        show_default=False,
    ),
):
    vol = Volatility(file, render, output)
    results = vol.run_x509(list(pids), list(procnames), bool(output))
    console.print(results)


@kernel_app.command(
    name="symcrypt", help="Scan a kernel-mode dump for symcrypt objects"
)
def kernel_symcrypt(
    file: Path = typer.Option(
        ..., "--file", "-f", help="Path to kernel dump", dir_okay=False
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Path to dump objects to disk", file_okay=False
    ),
    pids: List[int] = typer.Option(
        [], "--pid", "-p", help="Pids to scan. Can be passed multiple times."
    ),
    procnames: List[str] = typer.Option(
        [],
        "--procname",
        "-n",
        help="Process names to scan. Can be passed multiple times.",
        callback=lowercase_list,
    ),
    render: RichRenderOption = typer.Option(
        RichRenderOption.TABLE,
        "--render",
        "-r",
        help="Render output (default: table)",
        case_sensitive=False,
        show_default=False,
    ),
):
    vol = Volatility(file, render, output)
    results = vol.run_symcrypt(list(pids), list(procnames), bool(output))
    console.print(results)


@minidump_app.command(name="x509", help="Scan a minidump for x509 objects")
def minidump_x509(
    file: Path = typer.Option(
        ..., "--file", "-f", help="Path to minidump", dir_okay=False
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Path to dump objects to disk", file_okay=False
    ),
):
    minidump_file = MinidumpFile(file.absolute())
    scanner = x509Scanner.minidump_scan(minidump_file, output)
    console.print(scanner)


# @minidump_app.command(name="bcrypt", help="Scan a minidump for BCrypt objects")
# def minidump_bcrypt(
#     file: Path = typer.Option(
#         ..., "--file", "-f", help="Path to minidump", dir_okay=False
#     ),
#     output: Path = typer.Option(
#         None, "--output", "-o", help="Path to dump objects to disk", file_okay=False
#     ),
# ):
#     minidump_file = MinidumpFile(file.absolute())
#     scanner = x509Scanner.minidump_scan(minidump_file, output)
#     console.print(scanner)


@minidump_app.command(name="symcrypt", help="Scan a minidump for symcrypt objects")
def minidump_symcrypt(
    file: Path = typer.Option(
        ..., "--file", "-f", help="Path to kernel dump", dir_okay=False
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Path to dump objects to disk", file_okay=False
    ),
):

    # Get all the public certs first
    minidump_file = MinidumpFile(file.absolute())
    x509_scanner = x509Scanner.minidump_scan(minidump_file, None)

    # Now look for symcrypt
    symcrypt_scanner = SymcryptScanner.minidump_scan(
        minidump_file, x509_scanner, output
    )
    console.print(symcrypt_scanner)


@minidump_app.command(name="envar", help="Dump the environment variables in a minidump")
def minidump_envar(
    file: Path = typer.Option(
        ..., "--file", "-f", help="Path to kernel dump", dir_okay=False
    ),
):
    # Get all the public certs first
    minidump_file = MinidumpFile(file.absolute())
    # print(minidump_file.dump)

    envars = minidump_file.get_envars()
    table = get_dumpscan_table()
    table.add_column("Variable", style="italic #f9c300")
    table.add_column("Value")
    [table.add_row(k, v) for k, v in envars.items()]
    console.print(table, highlight=False)


@minidump_app.command(name="cmdline", help="Dump the command line string")
def minidump_cmdline(
    file: Path = typer.Option(
        ..., "--file", "-f", help="Path to kernel dump", dir_okay=False
    ),
):
    # Get all the public certs first
    minidump_file = MinidumpFile(file.absolute())
    console.print(
        minidump_file.get_commandline(),
        "\n",
        style="#f9c300",
        highlight=False,
    )


if __name__ == "__main__":
    app()
