"""Main entry point for the desktop application."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from .config import (
    APP_NAME,
    APP_TITLE,
    APP_VERSION,
    AppConfig,
    ConfigStore,
    configure_logging,
    data_dir,
    ensure_dir,
)
from .database import Database
from .gui import MainWindow
from .security import SECURITY_GUARANTEES

LOGGER = logging.getLogger(__name__)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Authorized keyboard-event monitoring tool for controlled lab environments.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to a custom config.json (optional).",
    )
    parser.add_argument(
        "--database",
        type=Path,
        help="Path to a custom SQLite database (optional).",
    )
    parser.add_argument(
        "--simulation",
        action="store_true",
        help="Start in Simulation Mode (does not touch the real keyboard).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )
    return parser.parse_args(argv[1:])


def ensure_directories(config: AppConfig) -> None:
    ensure_dir(data_dir())
    ensure_dir(data_dir() / "logs")
    ensure_dir(config.database_path.parent)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv)
    store = ConfigStore(args.config if args.config else None)
    config = store.load()

    if args.simulation:
        config.simulation_mode = True

    log_level = "DEBUG" if args.verbose else config.log_level
    configure_logging(log_level)

    LOGGER.info("%s %s starting", APP_NAME, APP_VERSION)
    LOGGER.info(
        "Security guarantees: %s",
        "; ".join(SECURITY_GUARANTEES[:2]),
    )

    ensure_directories(config)
    database_path = args.database if args.database else config.database_path
    database = Database(database_path)
    try:
        database.initialize()
    except Exception as exc:
        LOGGER.error("Could not initialise the database: %s", exc)
        return 1

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_TITLE)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("AuthorizedSecurityLab")

    window = MainWindow(config=config, database=database, store=store)
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())