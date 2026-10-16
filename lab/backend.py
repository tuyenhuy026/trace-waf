"""Deliberately vulnerable localhost lab; all records and files are synthetic."""
import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path('/tmp/trace-fixture')
(ROOT / 'public').mkdir(parents=True, exist_ok=True)
(ROOT / 'public' / 'readme.txt').write_text('PUBLIC_DOCUMENT')
(ROOT / 'secret.txt').write_text('TRACE_FILE_SECRET')


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query, keep_blank_values=True).get('q', [''])[0]
        status, mime, body = 200, 'text/html; charset=utf-8', ''
        if parsed.path == '/health':
            body = 'ok'
        elif parsed.path == '/sql':
            db = sqlite3.connect(':memory:')
            db.executescript("CREATE TABLE items(name TEXT, public INT); INSERT INTO items VALUES ('apple',1),('TRACE_SQL_SECRET',0);")
            try:
                rows = db.execute("SELECT name FROM items WHERE public=1 AND name='" + q + "'").fetchall()
                body = json.dumps(rows)
            except sqlite3.Error as exc:
                body = json.dumps({'error': str(exc)})
            finally:
                db.close()
            mime = 'application/json'
        elif parsed.path == '/xss':
            body = '<!doctype html><html><body>' + q + '</body></html>'
        elif parsed.path in ('/docs', '/search'):
            body = '<!doctype html><html><body>' + html.escape(q) + '</body></html>'
        elif parsed.path == '/file':
            target = (ROOT / 'public' / q).resolve()
            # Contain the deliberately vulnerable exercise within fixture files.
            if target.is_relative_to(ROOT) and target.is_file():
                body = target.read_text()
            else:
                status, body = 404, 'not found'
            mime = 'text/plain'
        else:
            status, body = 404, 'not found'
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('X-Trace-Request', self.headers.get('X-Trace-Request', ''))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        print(json.dumps({'request_id': self.headers.get('X-Trace-Request'), 'message': fmt % args}), flush=True)


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
