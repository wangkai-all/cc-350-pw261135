"""Operations web console (stdlib only).

Pages
-----
/                 dashboard: package directory, gaps, per-record cross-package
                  positions, quarantine reasons, worker status
/events           audit journal (all state transitions)
/api/state        JSON snapshot for automation/verification
POST /api/ingest  upload a package -> lands in inbox (补包 / replacement)
POST /api/manifest upload a manifest JSON (换版)
POST /api/worker/restart | /stop | /start
"""

from __future__ import annotations

import argparse
import cgi
import html
import json
import os
import signal
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

if __package__ in (None, ""):  # executed directly under `python -I app/webapp.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.directory import PackageDirectoryService
from app.storage import Storage
from app import __version__

BADGE = {
    "OK": "#1a7f37", "MISSING": "#9a6700", "QUARANTINED": "#cf222e",
    "SUPERSEDED": "#8250df", "SUPERSEDED_AWAITING_REPLACEMENT": "#bf8700",
    "PUBLISHED": "#1a7f37", "ASSEMBLING": "#9a6700",
    "BAD": "#cf222e", "RECEIVED": "#1a7f37", "PENDING": "#9a6700",
}


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def badge(state: str) -> str:
    color = BADGE.get(state, "#57606a")
    return ('<span class="badge" style="background:%s">%s</span>'
            % (color, esc(state)))


CSS = """
body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:0;
background:#f6f8fa;color:#1f2328;font-size:13px}
header{background:#24292f;color:#fff;padding:10px 20px;display:flex;
justify-content:space-between;align-items:center}
header a{color:#79c0ff;margin-left:16px;text-decoration:none}
main{padding:18px 24px;max-width:1180px;margin:0 auto}
h2{margin:26px 0 8px;font-size:15px}
table{border-collapse:collapse;width:100%;background:#fff;
border:1px solid #d0d7de;border-radius:6px;overflow:hidden}
th,td{padding:6px 9px;border-bottom:1px solid #d8dee4;text-align:left;
vertical-align:top}
th{background:#f0f3f6;font-weight:600}
tr:last-child td{border-bottom:none}
.badge{color:#fff;padding:2px 7px;border-radius:10px;font-size:11px;
white-space:nowrap}
.gap{color:#cf222e;font-weight:700}
form{display:inline-block;margin:4px 8px 4px 0;background:#fff;
border:1px solid #d0d7de;border-radius:6px;padding:10px}
button{background:#0969da;color:#fff;border:0;border-radius:5px;
padding:5px 12px;cursor:pointer;font-family:inherit}
button.danger{background:#cf222e}
button.neutral{background:#57606a}
.muted{color:#57606a}.reason{color:#cf222e;max-width:420px}
.pos{font-size:12px}.ok2{color:#1a7f37}.miss2{color:#9a6700}.bad2{color:#cf222e}
.flash{background:#dafbe1;border:1px solid #1a7f37;padding:8px 12px;
border-radius:6px;margin:10px 0}
.flash.err{background:#ffebe9;border-color:#cf222e}
code{background:#eef1f4;padding:1px 4px;border-radius:3px}
"""


class WorkerControl:
    """Starts/stops the daemon worker as a child process of the web server."""

    def __init__(self, data_root: Path):
        self.data_root = data_root
        self.pid_file = data_root / "worker" / "worker.pid"
        self.heartbeat = data_root / "worker" / "heartbeat"
        self.log_file = data_root / "worker" / "worker.log"
        self.proc: subprocess.Popen | None = None

    def alive_pid(self) -> int | None:
        if self.proc is not None and self.proc.poll() is None:
            return self.proc.pid
        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
                os.kill(pid, 0)
                return pid
            except (ValueError, OSError):
                return None
        return None

    def status(self) -> dict:
        pid = self.alive_pid()
        hb = None
        if self.heartbeat.exists():
            try:
                hb = time.time() - float(self.heartbeat.read_text().strip())
            except ValueError:
                hb = None
        return {"running": pid is not None, "pid": pid,
                "heartbeat_age_s": round(hb, 2) if hb is not None else None}

    def start(self) -> int:
        if self.alive_pid() is not None:
            return -1
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        log = open(self.log_file, "ab", buffering=0)
        launcher = Path(__file__).resolve().parent.parent / "bin" / "worker"
        self.proc = subprocess.Popen(
            [str(launcher), "--data", str(self.data_root)],
            cwd=str(Path(__file__).resolve().parent.parent),
            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
        return self.proc.pid

    def stop(self) -> bool:
        pid = self.alive_pid()
        if pid is None:
            return False
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return False
        deadline = time.time() + 8
        while time.time() < deadline:
            if self.alive_pid() is None:
                return True
            time.sleep(0.2)
        os.kill(pid, signal.SIGKILL)
        return True

    def restart(self) -> int:
        self.stop()
        return self.start()


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "PointwiseConsole/" + __version__
    storage: Storage
    directory: PackageDirectoryService
    workers: WorkerControl

    def log_message(self, fmt, *args):  # quiet default stderr logging
        sys.stderr.write("[web] %s - %s\n" % (self.address_string(), fmt % args))

    # ------------------------------------------------------------------ #
    def _send(self, code: int, body: str | bytes, ctype: str = "text/html; charset=utf-8",
              extra_headers: list[tuple[str, str]] | None = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra_headers or []:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, indent=2, default=str),
                   "application/json; charset=utf-8")

    def _flash(self) -> str:
        qs = parse_qs(urlparse(self.path).query)
        msg = qs.get("msg", [None])[0]
        err = qs.get("err", [None])[0]
        if msg:
            return '<div class="flash">%s</div>' % esc(msg)
        if err:
            return '<div class="flash err">%s</div>' % esc(err)
        return ""

    # ------------------------------------------------------------------ #
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/":
                self._send(200, self._render_dashboard())
            elif path == "/events":
                self._send(200, self._render_events())
            elif path == "/api/state":
                self._json(self._state_snapshot())
            elif path == "/api/worker":
                self._json(self.workers.status())
            else:
                self._send(404, "not found", "text/plain; charset=utf-8")
        except Exception as exc:  # console must never crash the server
            self._send(500, "internal error: %s" % esc(exc),
                       "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/ingest":
                self._handle_upload(kind="package")
            elif path == "/api/manifest":
                self._handle_upload(kind="manifest")
            elif path == "/api/worker/restart":
                pid = self.workers.restart()
                self._redirect("worker restarted (pid=%s)" % pid)
            elif path == "/api/worker/stop":
                self.workers.stop()
                self._redirect("worker stopped")
            elif path == "/api/worker/start":
                pid = self.workers.start()
                self._redirect("worker started (pid=%s)" % pid
                               if pid > 0 else "worker already running",
                               is_err=pid <= 0)
            else:
                self._send(404, "not found", "text/plain; charset=utf-8")
        except Exception as exc:
            self._redirect(str(exc), is_err=True)

    # ------------------------------------------------------------------ #
    def _handle_upload(self, *, kind: str) -> None:
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            raise ValueError("expected multipart/form-data upload")
        length = int(self.headers.get("Content-Length", "0"))
        env = {"REQUEST_METHOD": "POST", "CONTENT_TYPE": ctype,
               "CONTENT_LENGTH": str(length)}
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ=env, keep_blank_values=True)
        item = form["file"]
        if not getattr(item, "filename", None):
            raise ValueError("no file selected")
        data = item.file.read()
        if kind == "package":
            name = self._safe_upload_name(item.filename, ".pdpkg")
            dest = self.storage.inbox / name
            self.storage.atomic_write(dest, data)
            self._redirect("package %s (%d bytes) staged to inbox"
                           % (name, len(data)))
        else:
            name = self._safe_upload_name(item.filename, ".json")
            doc = json.loads(data.decode("utf-8"))
            dest = self.storage.delivery / name
            self.storage.atomic_write(dest, json.dumps(doc).encode())
            result = self.directory.apply_manifest_file(dest)
            self._redirect("manifest applied: %s" % json.dumps(result))

    @staticmethod
    def _safe_upload_name(filename: str, suffix: str) -> str:
        base = Path(filename).name
        if not base.endswith(suffix):
            base += suffix
        ts = time.strftime("%Y%m%d-%H%M%S")
        return "%s-%s%s" % (Path(base).stem, ts, suffix)

    def _redirect(self, message: str, *, is_err: bool = False) -> None:
        from urllib.parse import quote
        key = "err" if is_err else "msg"
        self._send(303, b"", extra_headers=[
            ("Location", "/?" + key + "=" + quote(message))])

    # ------------------------------------------------------------------ #
    def _state_snapshot(self) -> dict:
        return {
            "generated_at": time.time(),
            "worker": self.workers.status(),
            "package_directory": self.directory.package_directory(),
            "package_gaps": self.directory.package_gaps(),
            "records": self.directory.record_cross_positions(),
            "published": [dict(r) for r in self.storage.query(
                "SELECT tenant_id, record_id, sha256, record_len, file_path,"
                " published_at FROM published ORDER BY tenant_id, record_id")],
        }

    def _render_dashboard(self) -> str:
        snap = self._state_snapshot()
        parts = [self._shell("Dashboard"), self._flash()]
        w = snap["worker"]
        parts.append(
            "<h2>Worker</h2><table><tr><th>running</th><th>pid</th>"
            "<th>heartbeat age (s)</th></tr><tr>"
            f"<td>{esc(w['running'])}</td><td>{esc(w['pid'])}</td>"
            f"<td>{esc(w['heartbeat_age_s'])}</td></tr></table>"
            '<form method="post" action="/api/worker/start"><button>Start</button></form>'
            '<form method="post" action="/api/worker/restart"><button class="neutral">Restart</button></form>'
            '<form method="post" action="/api/worker/stop"><button class="danger">Stop</button></form>')

        parts.append("<h2>Operations</h2>"
                     '<form method="post" action="/api/ingest" enctype="multipart/form-data">'
                     '补包 / 换版包 (.pdpkg): <input type="file" name="file" required>'
                     ' <button>Upload to inbox</button></form>'
                     '<form method="post" action="/api/manifest" enctype="multipart/form-data">'
                     '换版清单 (.json): <input type="file" name="file" required>'
                     ' <button>Apply manifest</button></form>')

        parts.append(self._render_packages(snap))
        parts.append(self._render_records(snap))
        parts.append(self._render_published(snap))
        parts.append("</main></body></html>")
        return "".join(parts)

    def _render_packages(self, snap: dict) -> str:
        gaps = set(snap["package_gaps"])
        rows = []
        for p in snap["package_directory"]:
            gap_mark = ' <span class="gap">GAP</span>' if p["seq"] in gaps else ""
            got = ("v%s" % p["got_version"]) if p["got_version"] is not None else "-"
            segc = p["seg_count"] if p["seg_count"] is not None else "-"
            rows.append(
                f"<tr><td>{esc(p['seq'])}{gap_mark}</td>"
                f"<td>v{esc(p['expected_version'])}</td>"
                f"<td>{badge(p['status'])}</td>"
                f"<td>{esc(got)}</td><td>{esc(segc)}</td>"
                f"<td class='reason'>{esc(p['quarantine_reason'])}</td></tr>")
        return ("<h2>Package directory &amp; gaps</h2>"
                "<table><tr><th>seq</th><th>expected</th><th>state</th>"
                "<th>received</th><th>segments</th><th>quarantine reason</th></tr>"
                + "".join(rows) + "</table>"
                + '<p class="muted">missing sequences inside declared range: '
                + esc(snap["package_gaps"]) + "</p>")

    def _render_records(self, snap: dict) -> str:
        rows = []
        for r in snap["records"]:
            positions = []
            for p in r["positions"]:
                cls = ("ok2" if p["state"] == "OK"
                       else ("bad2" if p["state"] == "BAD" else "miss2"))
                mark = "" if p["state"] == "OK" else "✗"
                positions.append(
                    f"<span class='pos {cls}'>#{p['seg_index']}"
                    f"→pkg{esc(p['expected_seq'])}(v{esc(p['expected_version'])})"
                    f"{mark}</span>")
            pos = " ".join(positions)
            ok_count = (len(r["positions"])
                        - len(r["missing_segments"]) - len(r["bad_segments"]))
            rows.append(
                f"<tr><td>{esc(r['tenant_id'])}</td>"
                f"<td>{esc(r['record_id'])}</td>"
                f"<td>{badge(r['assembly_status'])}</td>"
                f"<td>{esc(ok_count)}/{esc(r['seg_total'])}</td>"
                f"<td>pkgs {esc(','.join(map(str, r['spans_packages'])))}</td>"
                f"<td class='reason'>{esc(r['quarantine_reason'])}</td>"
                f"<td class='pos'>{pos}</td></tr>")
        return ("<h2>Records: cross-package positions, gaps, isolation</h2>"
                "<table><tr><th>tenant</th><th>record</th><th>status</th>"
                "<th>segments ok/total</th><th>spans</th><th>isolation reason</th>"
                "<th>segment → package map</th></tr>" + "".join(rows) + "</table>")

    def _render_published(self, snap: dict) -> str:
        rows = [
            f"<tr><td>{esc(r['tenant_id'])}</td><td>{esc(r['record_id'])}</td>"
            f"<td><code>{esc(r['sha256'][:16])}</code></td>"
            f"<td>{esc(r['record_len'])}</td><td>{esc(r['file_path'])}</td></tr>"
            for r in snap["published"]]
        if not rows:
            rows = ["<tr><td colspan=5 class='muted'>nothing published yet</td></tr>"]
        return ("<h2>Published records (idempotent store)</h2><table><tr>"
                "<th>tenant</th><th>record</th><th>sha256</th><th>bytes</th>"
                "<th>file</th></tr>" + "".join(rows) + "</table>")

    def _render_events(self) -> str:
        rows = self.storage.query(
            "SELECT ts, kind, tenant_id, record_id, seq, detail FROM events"
            " ORDER BY id DESC LIMIT 300")
        body = [
            f"<tr><td>{esc(time.strftime('%H:%M:%S', time.localtime(r['ts'])))}</td>"
            f"<td>{esc(r['kind'])}</td><td>{esc(r['tenant_id'])}</td>"
            f"<td>{esc(r['record_id'])}</td><td>{esc(r['seq'])}</td>"
            f"<td>{esc(r['detail'])}</td></tr>"
            for r in rows]
        return (self._shell("Audit events") + self._flash()
                + "<h2>Audit journal (latest 300)</h2><table><tr><th>time</th>"
                "<th>event</th><th>tenant</th><th>record</th><th>seq</th>"
                "<th>detail</th></tr>" + "".join(body) + "</table></main></body></html>")

    def _shell(self, title: str) -> str:
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{esc(title)}</title><style>{CSS}</style></head><body>"
            "<header><b>Pointwise Delivery Console · "
            f"{esc(title)}</b><nav>"
            "<a href='/'>Dashboard</a><a href='/events'>Events</a>"
            "<a href='/api/state'>JSON</a></nav></header><main>"
        )


def build_server(data_root: str, host: str, port: int) -> ThreadingHTTPServer:
    root = Path(data_root).resolve()
    storage = Storage(root)
    directory = PackageDirectoryService(storage)
    workers = WorkerControl(root)
    handler = ConsoleHandler
    handler.storage = storage
    handler.directory = directory
    handler.workers = workers
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.storage = storage  # type: ignore[attr-defined]
    httpd.workers = workers  # type: ignore[attr-defined]
    return httpd


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="app.webapp",
                                 description="Operations web console")
    ap.add_argument("--data", default=os.environ.get("PDP_DATA", "data"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    args = ap.parse_args(argv)
    httpd = build_server(args.data, args.host, args.port)
    print("console listening on http://%s:%d  (data=%s)"
          % (args.host, args.port, args.data))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        httpd.storage.close()  # type: ignore[attr-defined]
    return 0


if __name__ == "__main__":
    sys.exit(main())
