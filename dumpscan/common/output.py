from rich import box
from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.theme import Theme

theme = Theme(
    {
        "repr.attrib_value": "#047bd6",
        "repr.call": Style.null(),
        "repr.ipv6 ": "#008df8",
        "repr.none": "italic #d24a00",
        "repr.number": "#008df8",
        "repr.str": "bright_blue",
        "table.border": "#0084a8",
        "table.cell": "#00a5fa",
        "table.header": "bold italic #d24a00",
    }
)


def get_dumpscan_console():
    return Console(theme=theme)


def get_dumpscan_table():
    return Table(
        expand=False, box=box.SIMPLE_HEAVY, highlight=True, border_style="#047bd6"
    )
