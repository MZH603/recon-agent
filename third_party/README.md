# Third-party tools

`tools/` contains upstream-provided scanners, binaries, and dictionaries. These files are kept as imported from the upstream repository. The Python package and wheel include only `agent/` and `tui/`; installing recon-agent does not install or run this directory.

Agent integrations must access external tools through the registered adapters and their authorization checks. Keep licenses and provenance in each upstream tool directory where provided.
