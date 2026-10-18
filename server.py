#!/usr/bin/env python3
"""Server for the QR scan-awareness page. Standard library only.

Routes:
  /              the page, with request details rendered into the HTML by the server
  /s/<sticker>   counts one scan for a known sticker, then redirects to /?s=<sticker>
  /api/counts    JSON totals per sticker (counts only, no visitor data)
  /healthz       health check

The app writes nothing about visitors: no IP addresses, no user agents, no
cookies. The hosting platform may keep its own request logs, which is outside
this file.

Environment:
  PORT         port to listen on (default 8080; hosts usually set this)
  COUNTS_FILE  where the sticker totals are saved (default data/counts.json)
"""
import html
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
PAGE = (ROOT / "index.html").read_text(encoding="utf-8")
COUNTS_FILE = Path(os.environ.get("COUNTS_FILE", str(ROOT / "data" / "counts.json")))

# Only these codes are counted. Anything else redirects without counting.
STICKERS = {
    "library": "Library notice board",
    "bus-stop": "Bus shelter",
    "cafe": "Café table",
    "campus": "Campus poster",
}

# Inline scripts and styles are allowed because the page uses them.
# That is why this policy is weaker than it could be.
CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "connect-src 'self' https://ipwho.is; "
    "img-src 'self' data: blob:; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)

_lock = threading.Lock()


def _load_counts():
    try:
        saved = json.loads(COUNTS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    return {code: int(saved.get(code, 0)) for code in STICKERS}


counts = _load_counts()


def count_scan(code):
    with _lock:
        counts[code] += 1
        try:
            COUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp = COUNTS_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(counts), encoding="utf-8")
            tmp.replace(COUNTS_FILE)
        except OSError:
            pass  # still counted in memory if the disk is read-only


def esc(value):
    return html.escape(value or "not sent", quote=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "scanpage"
    sys_version = ""

    def log_message(self, format, *args):
        pass  # the app writes no access log

    def client_ip(self):
        # Proxies append the address they received the connection from, so the
        # last X-Forwarded-For entry is the one to trust.
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[-1].strip()
        return self.client_address[0]

    def reply(self, status, body, ctype, extra=()):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), payment=(), geolocation=(self)")
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlsplit(self.path)
        path = url.path if url.path == "/" else url.path.rstrip("/")

        if path == "/healthz":
            return self.reply(200, "ok", "text/plain; charset=utf-8")

        if self.headers.get("X-Forwarded-Proto") == "http":
            host = self.headers.get("Host", "")
            return self.reply(301, "", "text/plain; charset=utf-8", [("Location", f"https://{host}{self.path}")])

        if path == "/api/counts":
            with _lock:
                snapshot = dict(counts)
            body = json.dumps({
                "total": sum(snapshot.values()),
                "by_sticker": {c: {"label": STICKERS[c], "count": snapshot[c]} for c in STICKERS},
            })
            return self.reply(200, body, "application/json")

        if path.startswith("/s/"):
            code = path[3:]
            if code in STICKERS:
                count_scan(code)
                return self.reply(303, "", "text/plain; charset=utf-8", [("Location", f"/?s={code}")])
            return self.reply(303, "", "text/plain; charset=utf-8", [("Location", "/")])

        if path == "/":
            return self.reply(200, self.render_home(parse_qs(url.query)), "text/html; charset=utf-8")

        return self.reply(404, "Not found", "text/plain; charset=utf-8")

    def render_home(self, query):
        h = self.headers
        code = query.get("s", [""])[0]
        came = ""
        if code in STICKERS:
            came = f'<p class="pill">You came in through the {esc(STICKERS[code])} sticker</p>'

        seen = [
            ("IP address", self.client_ip()),
            ("Browser", h.get("User-Agent")),
            ("Languages", h.get("Accept-Language")),
            ("Browser brand (client hint)", h.get("Sec-CH-UA")),
            ("Platform (client hint)", h.get("Sec-CH-UA-Platform")),
            ("Mobile (client hint)", h.get("Sec-CH-UA-Mobile")),
            ("Came from", h.get("Referer")),
            ("Global Privacy Control", "on" if h.get("Sec-GPC") == "1" else "off"),
            ("Data saver", "on" if h.get("Save-Data") == "on" else "off"),
        ]
        defences = [
            ("HTTPS enforced", "on", "The browser is told to use HTTPS for this site from now on."),
            ("Content Security Policy", "on", "Limits which scripts and connections the page may use. It still allows inline scripts, so it is weaker than it could be."),
            ("Clickjacking protection", "on", "Other sites cannot embed this page to trick people into clicking."),
            ("Referrer", "trimmed", "Other sites only receive this site's name, not the full address of the page."),
            ("Camera and microphone", "blocked", "Permissions-Policy switches them off. Location is allowed only for the GPS button."),
            ("MIME sniffing", "blocked", "Browsers must use the file type the server declares."),
        ]

        seen_rows = "".join(
            f'<div class="row"><span class="k">{esc(k)}</span><span class="v">{esc(v)}</span></div>'
            for k, v in seen
        )
        defence_rows = "".join(
            f'<div class="row"><span class="k">{esc(k)}</span><span class="v">{esc(v)}</span></div>'
            f'<p class="fine">{esc(note)}</p>'
            for k, v, note in defences
        )
        block = f"""
  <section class="server-seen" aria-labelledby="srv-h">
    <p class="eyebrow">Before any script ran</p>
    <h2 id="srv-h">What the server saw</h2>
    <p class="sub">Your browser sent all of this with the request for this page, before a single script on it ran. The server reads it, shows it back to you, and writes none of it down.</p>
    {came}
    <div class="tcard"><div class="r-group"><h3>Sent with your request</h3>{seen_rows}</div></div>
    <div class="tcard"><div class="r-group"><h3>This site's defences</h3>{defence_rows}</div></div>
  </section>"""
        return PAGE.replace("<!--SERVER_SEEN-->", block)


def main():
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
