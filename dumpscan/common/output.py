from rich import box
from rich.console import Console
from rich.table import Table
from rich.theme import Theme
from rich.style import Style

theme = Theme(
    {
        "repr.call": Style.null(),
        "repr.ipv6 ": "#008df8",
        "repr.none": "italic #d24a00",
        "repr.number": "#008df8",
        "repr.str": "bright_blue",
        "table.header": "bold italic #d24a00",
        "table.border": "#0084a8",
        "table.cell": "#00a5fa",
    }
)


def get_dumpscan_console():
    return Console(theme=theme)


def get_dumpscan_table():
    return Table(
        expand=False,
        box=box.SIMPLE_HEAVY,
        highlight=True,
        border_style="#0084a8",
    )
