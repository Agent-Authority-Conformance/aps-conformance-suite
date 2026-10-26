"""Run a Python script or module under an audit hook.

    python3 offline.py <script.py> [args...]
    python3 offline.py -m <module> [args...]

offline.py installs an audit hook in the interpreter that runs each
verification step. Socket and name-lookup calls from that interpreter are
refused. Child processes are not covered.
"""
import os
import runpy
import sys

BLOCKED = ("socket.__new__", "socket.connect", "socket.getaddrinfo",
           "socket.gethostbyname", "socket.gethostbyaddr", "urllib.Request")


def refuse(event, args):
    if event in BLOCKED:
        raise RuntimeError(f"network access refused: {event}")


if sys.argv[1] == "-m":
    module = sys.argv[2]
    sys.argv = sys.argv[2:]
    sys.path.insert(0, os.getcwd())
    sys.addaudithook(refuse)
    runpy.run_module(module, run_name="__main__", alter_sys=True)
else:
    script = os.path.abspath(sys.argv[1])
    sys.argv = sys.argv[1:]
    sys.path.insert(0, os.path.dirname(script))
    sys.addaudithook(refuse)
    runpy.run_path(script, run_name="__main__")
