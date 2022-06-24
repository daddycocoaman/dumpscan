import logging
import warnings

import rich_click as click
from cryptography.utils import CryptographyDeprecationWarning
from rich import traceback
from rich.logging import RichHandler

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
traceback.install(show_locals=True)

logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, show_path=False, show_time=False)],
)

# ***** RICH CLICK STYLE *****
click.rich_click.MAX_WIDTH = 100
# click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = True
click.rich_click.SHOW_METAVARS_COLUMN = True
click.rich_click.APPEND_METAVARS_HELP = False

click.rich_click.STYLE_HELPTEXT_FIRST_LINE = "#d24a00"

click.rich_click.STYLE_OPTION = "#f9c300"
click.rich_click.STYLE_OPTIONS_TABLE_BOX = "SIMPLE"
click.rich_click.STYLE_OPTIONS_PANEL_BORDER = "bold #0084a8"
click.rich_click.STYLE_OPTIONS_TABLE_ROW_STYLES = ["#f9c300"]

click.rich_click.STYLE_COMMANDS_TABLE_BOX = "SIMPLE"
click.rich_click.STYLE_COMMANDS_PANEL_BORDER = "bold #0084a8"
click.rich_click.STYLE_COMMANDS_TABLE_ROW_STYLES = ["#f9c300"]

click.rich_click.STYLE_USAGE = "bold #0084a8"
click.rich_click.STYLE_USAGE_COMMAND = "#d24a00 italic"
