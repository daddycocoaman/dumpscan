import logging
import warnings

from typer import rich_utils
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

# ***** TYPER RICH STYLE *****
rich_utils.MAX_WIDTH = 100
# rich_utils.USE_RICH_MARKUP = True
rich_utils.USE_MARKDOWN = True
rich_utils.SHOW_METAVARS_COLUMN = True
rich_utils.APPEND_METAVARS_HELP = False

rich_utils.STYLE_HELPTEXT_FIRST_LINE = "#d24a00"

rich_utils.STYLE_OPTION = "#f9c300"
rich_utils.STYLE_OPTIONS_TABLE_BOX = "SIMPLE"
rich_utils.STYLE_OPTIONS_PANEL_BORDER = "bold #0084a8"
rich_utils.STYLE_OPTIONS_TABLE_ROW_STYLES = ["#f9c300"]

rich_utils.STYLE_COMMANDS_TABLE_BOX = "SIMPLE"
rich_utils.STYLE_COMMANDS_PANEL_BORDER = "bold #0084a8"
rich_utils.STYLE_COMMANDS_TABLE_ROW_STYLES = ["#f9c300"]

rich_utils.STYLE_USAGE = "bold #0084a8"
rich_utils.STYLE_USAGE_COMMAND = "#d24a00 italic"
