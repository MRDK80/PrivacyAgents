"""Metadata-only entry point; no runtime effects."""

import argparse

from privacy_agents import __version__


def main() -> None:
    parser = argparse.ArgumentParser(description="PrivacyAgents package candidate")
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args()
    parser.print_help()
