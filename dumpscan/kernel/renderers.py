import logging
from enum import Enum

from rich import box
from volatility3.cli.text_renderer import QuickTextRenderer
from volatility3.framework import interfaces
from volatility3.framework.renderers import format_hints

from ..common.output import get_dumpscan_console, get_dumpscan_table

log = logging.getLogger("rich")


class RichTableRenderer(QuickTextRenderer):

    name = "richtable"

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """Renders each column using Rich Table output.
        Args:
            grid: The TreeGrid object to render
        """

        table = get_dumpscan_table()
        [table.add_column(c.name, overflow="fold") for c in grid.columns]

        # This function doesn't need to return anything at all and just updates existing Table object
        def visitor(node: interfaces.renderers.TreeNode, accumulator: None) -> None:
            row = []
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                column_rich_text = renderer(node.values[column_index])
                if column_index == 0:
                    column_str = "|" if node.path_depth - 1 else ""
                    row.append(
                        column_str + "-" * (node.path_depth - 1) + str(column_rich_text)
                    )
                else:
                    row.append(str(column_rich_text))
            table.add_row(*row)

        if not grid.populated:
            grid.populate(visitor, None)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=None)

        return table


class RichTextRenderer(QuickTextRenderer):

    name = "richtext"

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """Renders each column using Rich Table output.
        Args:
            grid: The TreeGrid object to render
        """

        console = get_dumpscan_console()

        line = []
        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            line.append(f"{column.name}")
        console.print("\n{}".format("\t".join(line)))

        def visitor(node: interfaces.renderers.TreeNode, accumulator: Console):
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            accumulator.print(
                "*" * max(0, node.path_depth - 1)
                + ("" if (node.path_depth <= 1) else " ")
            )
            line = []
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                line.append(renderer(node.values[column_index]))
            accumulator.print("{}".format("\t".join(line)), end="")
            accumulator.file.flush()
            return accumulator

        if not grid.populated:
            grid.populate(visitor, console)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=console)

        return "\n"


class RichRenderOption(str, Enum):
    TABLE = "table"
    TEXT = "text"

    def __init__(self, render: str) -> None:
        if render == "table":
            self.renderer = RichTableRenderer()
        else:
            self.renderer = RichTextRenderer()
