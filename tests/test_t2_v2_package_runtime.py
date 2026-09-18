"""The explicit delivery manifest must include runtime imports; no ZIP needed."""
import ast
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

from scripts import package_t2_v2 as package


class PackageRuntimeTests(unittest.TestCase):
    def test_relative_imports_are_in_the_explicit_manifest(self):
        modules = {"vulngym_t2." + name for name in package.MODULES}
        modules.update("vulngym_t2._vendor." + name for name in package.VENDOR)
        modules.update({"vulngym_t2", "vulngym_t2._vendor"})
        for name in sorted(modules):
            path = package.ROOT.joinpath(*name.split(".")).with_suffix(".py")
            if not path.is_file():
                continue  # Package directories have their own __init__ entry.
            parent = name.rsplit(".", 1)[0]
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.ImportFrom) or not node.level:
                    continue
                base = parent.split(".")[:len(parent.split(".")) - node.level + 1]
                if node.module:
                    dependencies = [".".join(base + node.module.split("."))]
                else:
                    dependencies = [".".join(base + [item.name]) for item in node.names]
                for dependency in dependencies:
                    with self.subTest(source=name, dependency=dependency):
                        self.assertIn(dependency, modules)

    def test_clean_source_tree_imports_without_repository_fallback(self):
        with tempfile.TemporaryDirectory(prefix="t2-package-runtime-") as temporary:
            destination = Path(temporary)
            assets = ("index.html", "app.css", "app.js", "brand/vulngym.png", "brand/README.md",
                      "fonts/jetbrains-mono-latin-wght-normal.woff2", "fonts/OFL.txt", "fonts/README.md")
            expected = {f"vulngym_t2/{name}.py" for name in package.MODULES}
            expected.update(f"vulngym_t2/_vendor/{name}.py" for name in package.VENDOR)
            expected.update(f"vulngym_t2/web_assets/{name}" for name in assets)
            delivery = json.loads((package.ROOT / "DELIVERY.json").read_text(encoding="utf-8"))
            runtime = delivery["runtime_source_files"]
            self.assertEqual(set(runtime), expected)
            self.assertEqual(len(runtime), len(expected))
            for name in runtime:
                target = destination / name
                self.assertTrue(target.resolve().is_relative_to(destination.resolve()))
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(package.ROOT / name, target)
            names = ["vulngym_t2." + name for name in package.MODULES
                     if name != "__main__"]
            code = textwrap.dedent("""
                import contextlib, http.client, importlib, io, json, runpy, socket, sys, threading
                from pathlib import Path

                root = Path(sys.argv[1]).resolve()
                module_names, asset_names = json.loads(sys.argv[2]), json.loads(sys.argv[3])
                original_root = Path(sys.argv[4]).resolve()
                # The portable interpreter intentionally adds its unpacked root to sys.path.
                # Remove it here so this probe cannot fall back to the original package.
                sys.path = [path for path in sys.path
                            if not path or Path(path).resolve() != original_root]
                assert all(Path(path).resolve() != original_root for path in sys.path if path)
                sys.path.insert(0, str(root))
                [importlib.import_module(name) for name in module_names]
                from vulngym_t2 import llm, web

                attempts = {"model_or_ledger": 0, "manager": 0, "external_network": 0}
                def no_model_or_ledger(*args, **kwargs):
                    attempts["model_or_ledger"] += 1
                    raise AssertionError("CLI help and static assets must not construct a model or ledger")
                llm.DeepSeekClient.__init__ = no_model_or_ledger
                llm.RequestLedger.__init__ = no_model_or_ledger

                output = io.StringIO()
                sys.argv = ["vulngym_t2", "--help"]
                with contextlib.redirect_stdout(output):
                    try:
                        runpy.run_module("vulngym_t2", run_name="__main__", alter_sys=True)
                    except SystemExit as exc:
                        assert exc.code == 0, exc.code
                    else:
                        raise AssertionError("CLI __main__ must finish through its exit status")
                assert "--prepare-only" in output.getvalue()
                assert "--input" in output.getvalue()
                assert "--request-ledger" in output.getvalue()

                class NoRunManager:
                    def __getattr__(self, name):
                        attempts["manager"] += 1
                        raise AssertionError("Static requests must not call a run manager: " + name)

                assert web.ASSETS.resolve() == root / "vulngym_t2" / "web_assets"
                for name in asset_names:
                    assert (web.ASSETS / name).is_file(), name
                    assert (web.ASSETS / name).stat().st_size > 0, name
                original_connect = socket.socket.connect
                original_connect_ex = socket.socket.connect_ex
                port = None
                def local_connect(connection, address):
                    if address != ("127.0.0.1", port):
                        attempts["external_network"] += 1
                        raise AssertionError("Only this temporary loopback server is allowed")
                    return original_connect(connection, address)
                def no_connect_ex(*args):
                    attempts["external_network"] += 1
                    raise AssertionError("Unexpected socket connection")
                socket.socket.connect = local_connect
                socket.socket.connect_ex = no_connect_ex
                server = None
                worker = None
                served = []
                try:
                    server = web.LocalServer(NoRunManager(), port=0)
                    port = server.server_port
                    assert server.server_address[0] == "127.0.0.1"
                    worker = threading.Thread(target=server.serve_forever,
                                              kwargs={"poll_interval": .01}, daemon=True)
                    worker.start()
                    routes = {"/": "text/html; charset=utf-8", **web.STATIC_TYPES}
                    assert len(routes) == 7
                    for route, content_type in routes.items():
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            connection.request("GET", route)
                            response = connection.getresponse()
                            data = response.read()
                            assert response.status == 200, (route, response.status)
                            assert response.getheader("Content-Type") == content_type
                            assert int(response.getheader("Content-Length")) == len(data)
                            name = "index.html" if route == "/" else route[1:]
                            expected = (web.ASSETS / name).read_bytes()
                            if route == "/":
                                assert b"__SESSION_TOKEN__" in expected
                                expected = expected.decode("utf-8").replace(
                                    "__SESSION_TOKEN__", server.token).encode("utf-8")
                                assert b"__SESSION_TOKEN__" not in data
                                assert server.token.encode("ascii") in data
                            assert data == expected, route
                            served.append(name)
                        finally:
                            connection.close()
                    # The eighth packaged asset is an offline font README,
                    # not a public static route; preserve that route contract.
                    assert set(asset_names) - set(served) == {"fonts/README.md"}
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        connection.request("GET", "/fonts/README.md")
                        response = connection.getresponse()
                        assert response.status == 404
                        assert json.loads(response.read())["code"] == "not_found"
                    finally:
                        connection.close()
                finally:
                    if server is not None:
                        if worker is not None and worker.is_alive():
                            server.shutdown()
                        server.server_close()
                    if worker is not None:
                        worker.join(5)
                        assert not worker.is_alive(), "Temporary Web server did not stop"
                    socket.socket.connect = original_connect
                    socket.socket.connect_ex = original_connect_ex

                imported = []
                for name, module in tuple(sys.modules.items()):
                    if name == "vulngym_t2" or name.startswith("vulngym_t2."):
                        filename = Path(module.__file__).resolve()
                        assert filename.is_relative_to(root), (name, str(filename))
                        imported.append(name)
                assert set(module_names).issubset(imported)
                assert attempts == {"model_or_ledger": 0, "manager": 0, "external_network": 0}, attempts
                print(json.dumps({"cli_help": True, "packaged_assets": len(asset_names),
                                  "served_assets": len(served), "server_stopped": True,
                                  "repository_fallback": False, "attempts": attempts}))
            """)
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code,
                                     str(destination), json.dumps(names), json.dumps(assets),
                                     str(package.ROOT)], cwd=destination,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            check = json.loads(result.stdout)
            self.assertTrue(check["cli_help"])
            self.assertEqual((check["packaged_assets"], check["served_assets"]), (8, 7))
            self.assertTrue(check["server_stopped"])
            self.assertFalse(check["repository_fallback"])
            self.assertEqual(check["attempts"],
                             {"model_or_ledger": 0, "manager": 0, "external_network": 0})


if __name__ == "__main__":
    unittest.main()
