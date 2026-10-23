# sec-portable

Single-binary offline edition: Server, Worker and Updater run in one process,
the web UI is embedded and storage is SQLite on numeric loopback only. The
launcher lives in `internal/portable`; build it with `make portable`. See
[docs/portable.md](../../docs/portable.md).

The Windows build embeds `icon.ico` (blue play button) through `rsrc_windows_amd64.syso`, which Go links automatically for windows/amd64. Regenerate both with `python3 scripts/gen_windows_icon.py`.
