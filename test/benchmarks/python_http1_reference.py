"""ASGI /binary endpoint served by pinned Uvicorn in compare_http1.py."""

BODY = bytes((0, 255, 13, 10, 65))
HEADERS = (
    (b"content-type", b"application/octet-stream"),
    (b"content-length", b"5"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"SAMEORIGIN"),
    (b"content-security-policy", b"default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
)


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    if scope["method"] != "GET" or scope["path"] != "/binary":
        await send({"type": "http.response.start", "status": 404,
                    "headers": [(b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b""})
        return
    await send({"type": "http.response.start", "status": 200, "headers": HEADERS})
    await send({"type": "http.response.body", "body": BODY})
