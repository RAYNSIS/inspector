#!/bin/sh
# Finds a working Python 3.9+ and hands the hook to it.
#
# `python3` alone is not enough on Windows: with the python.org installer the name is a Microsoft Store
# shortcut that prints an install hint and fails, while the real interpreter is `python` or `py -3`.
# POSIX sh only, and no external commands, so the usual case costs nothing but this shell.

case "$0" in
  *[\\/]*) root=${0%[\\/]*}/.. ;;
  *) root=${CLAUDE_PLUGIN_ROOT:-..} ;;
esac
launcher=$root/bin/raynsis-inspector
probe='import sys; sys.exit(sys.version_info < (3, 9))'

# Usual case: a real python3. One under WindowsApps may be the dead shortcut, so it is probed below instead.
found=$(command -v python3 2>/dev/null) || found=
case "$found" in
  ""|*WindowsApps*) ;;
  *) exec python3 "$launcher" "$@" ;;
esac

for py in python3 python; do
  "$py" -c "$probe" </dev/null >/dev/null 2>&1 && exec "$py" "$launcher" "$@"
done
py -3 -c "$probe" </dev/null >/dev/null 2>&1 && exec py -3 "$launcher" "$@"

echo "RAYNSIS Inspector: no working Python 3.9+ found (tried python3, python, py -3). Nothing is checked until one is on PATH." >&2
exit 1
