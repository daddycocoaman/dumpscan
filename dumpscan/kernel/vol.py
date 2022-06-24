import logging
from enum import Enum
from pathlib import Path
from typing import List

from rich import inspect, print
from volatility3 import framework, plugins
from volatility3.framework import (
    automagic,
    constants,
    contexts,
    interfaces,
    objects,
    renderers,
)
from volatility3.plugins.linux.pslist import PsList as NixPsList
from volatility3.plugins.mac.pslist import PsList as MacPsList
from volatility3.plugins.windows.pslist import PsList as WinPsList

from .filehandler import DumpscanFileHandler
from .plugins.dumpcerts import Dumpcerts
from .plugins.symcrypt import Symcrypt
from .renderers import RichRenderOption

from volatility3.plugins.windows.envars import Envars  # isort: skip
from volatility3.plugins.windows.cmdline import CmdLine

log = logging.getLogger("rich")


class OS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MAC = "mac"


PSLIST_PLUGINS = {OS.WINDOWS: WinPsList, OS.LINUX: NixPsList, OS.MAC: MacPsList}


class Volatility:
    def __init__(
        self, dumpfile: Path, renderer: RichRenderOption, output_dir: Path
    ) -> None:
        # Ensure minimum framework version
        framework.require_interface_version(2, 0, 0)

        self.dumpfile = dumpfile
        self.ctx = contexts.Context()
        self.ctx.config[
            "automagic.LayerStacker.single_location"
        ] = self.dumpfile.as_uri()
        self.automagics = automagic.available(self.ctx)

        # Add the plugins path to framework plugins path
        plugins.__path__ = [
            str(Path(__file__).parent / "plugins")
        ] + constants.PLUGINS_PATH
        framework.import_files(plugins, True)

        # Add a file handler
        self.file_handler = DumpscanFileHandler
        if output_dir:
            self.file_handler.output_dir = output_dir

        # Set the render mode
        self.render_mode = renderer

    def _run_plugin(self, plugin: interfaces.plugins.PluginInterface):
        """Runs a plugin"""
        automagics = automagic.choose_automagic(self.automagics, plugin)
        plugin = framework.plugins.construct_plugin(
            self.ctx, automagics, plugin, "plugins", None, self.file_handler
        )
        log.debug("Context config:", self.ctx.config)

        results: renderers.TreeGrid = plugin.run()
        return self.render_mode.renderer.render(results)

    def run_x509(self, pids: List[int], procnames: List[str], dump: bool):
        """Runs dumpcerts plugin on a kernel dump

        Args:
            pids (List[int]): List of pids to filter on
        """

        self.ctx.config["plugins.Dumpcerts.pid"] = pids
        self.ctx.config["plugins.Dumpcerts.name"] = procnames
        self.ctx.config["plugins.Dumpcerts.dump"] = dump

        return self._run_plugin(Dumpcerts)

    def run_symcrypt(self, pids: List[int], procnames: List[str], dump: bool):
        """Runs symcrypt plugin on a kernel dump

        Args:
            pids (List[int]): List of pids to filter on
        """

        self.ctx.config["plugins.Symcrypt.pid"] = pids
        self.ctx.config["plugins.Symcrypt.name"] = procnames
        self.ctx.config["plugins.Symcrypt.dump"] = dump

        return self._run_plugin(Symcrypt)

    def run_pslist(self, os: OS):
        """Runs the pslist plugin for appropriate operating system

        Args:
            os (OS): Operating System
        """
        pslist_plugin = PSLIST_PLUGINS.get(os)
        return self._run_plugin(pslist_plugin)

    def run_envar(self, pids: List[int]):
        """Runs envar plugin on a kernel dump

        Args:
            pids (List[int]): List of pids to filter on
        """
        self.ctx.config["plugins.Envars.pid"] = pids

        return self._run_plugin(Envars)

    def run_cmdline(self, pids: List[int]):
        """Runs cmdline plugin on a kernel dump

        Args:
            pids (List[int]): List of pids to filter on
        """
        self.ctx.config["plugins.CmdLine.pid"] = pids

        return self._run_plugin(CmdLine)
