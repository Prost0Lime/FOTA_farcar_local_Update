from mitmproxy import http
import os, re

# Путь к прошивке
ZIP_PATH = r"C:\fw\fu-5af72-13c0-4c57-98a7-bce3fc2309ab.zip"
MIME = "application/zip"

# Ловим любые iotdown-*.mayitek.com и .zip в URL
HOST_RE = re.compile(r"(^|\.)mayitek\.com$", re.IGNORECASE)

def _send_range(flow: http.HTTPFlow, start: int, end: int, total: int):
    length = end - start + 1
    with open(ZIP_PATH, "rb") as f:
        f.seek(start)
        data = f.read(length)
    flow.response = http.Response.make(
        206, data,
        {
            "Content-Type": MIME,
            "Accept-Ranges": "bytes",
            "Content-Length": str(length),
            "Content-Range": f"bytes {start}-{end}/{total}",
            "Content-Encoding": "identity",
            "Cache-Control": "no-transform",
            "Connection": "close",
        },
    )
    print(f"[SEND 206] {start}-{end}/{total} ({length} bytes)")

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    url  = flow.request.pretty_url
    method = flow.request.method.upper()
    print(f"[REQ] {method} {url}")

    # интересует только HTTP на *.mayitek.com и .zip в URL
    if not HOST_RE.search(host):
        return
    if ".zip" not in url.lower():
        return

    try:
        total = os.path.getsize(ZIP_PATH)
    except Exception as e:
        flow.response = http.Response.make(500, f"ZIP not found: {e}".encode("utf-8"))
        print(f"[ERR] ZIP not found: {e}")
        return

    # HEAD -> только заголовки
    if method == "HEAD":
        flow.response = http.Response.make(
            200, b"",
            {
                "Content-Type": MIME,
                "Accept-Ranges": "bytes",
                "Content-Length": str(total),
                "Content-Encoding": "identity",
                "Cache-Control": "no-transform",
                "Connection": "close",
            },
        )
        print(f"[HEAD 200] size={total}")
        return

    # Range (частичная выдача)
    rng = flow.request.headers.get("Range")
    if rng:
        # Пример: bytes=0-52428799  или bytes=52428800-
        m = re.match(r"bytes=(\d*)-(\d*)", rng.strip(), re.IGNORECASE)
        if m:
            s, e = m.groups()
            start = int(s) if s else 0
            end = int(e) if e else total - 1
            if end >= total: end = total - 1
            if start < 0 or start > end:
                flow.response = http.Response.make(
                    416, b"", {"Content-Range": f"bytes */{total}", "Connection": "close"}
                )
                print(f"[416] bad range: {rng}")
                return
            _send_range(flow, start, end, total)
            return
        else:
            print(f"[WARN] unsupported Range '{rng}', sending FULL")

    # Полностью
    with open(ZIP_PATH, "rb") as f:
        data = f.read()
    flow.response = http.Response.make(
        200, data,
        {
            "Content-Type": MIME,
            "Accept-Ranges": "bytes",
            "Content-Length": str(total),
            "Content-Encoding": "identity",
            "Cache-Control": "no-transform",
            "Connection": "close",
        },
    )
    print(f"[SEND 200] FULL size={total}")
