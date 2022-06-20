from rich import box
from rich.console import Console
from rich.table import Table
from rich.theme import Theme

theme = Theme(
    {
        "repr.call": "bold italic #00d8eb",
        "repr.ipv6 ": "#008df8",
        "repr.number": "#008df8",
        "repr.str": "bright_blue",
        "table.header": "bold italic #00d8eb",
        "table.border": "#e1251b",
        "table.cell": "#8ce10b",
    }
)


def get_dumpscan_console():
    return Console(theme=theme)


def get_dumpscan_table():
    return Table(
        expand=False,
        box=box.SIMPLE_HEAVY,
        highlight=True,
        border_style="#e1251b",
    )
