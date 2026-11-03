"""Trust the client address only on the private Nginx Unix-socket upstream."""

from ipaddress import ip_address


class UnixProxy:
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        try:
            if environ.get("REMOTE_ADDR"):
                raise ValueError("A Unix-socket upstream is required.")
            address = str(ip_address(environ.get("HTTP_X_REAL_IP", "")))
        except ValueError:
            body = b"Invalid proxy connection.\n"
            start_response("400 Bad Request", [
                ("Content-Type", "text/plain"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
            ])
            return [body]
        environ["REMOTE_ADDR"] = address
        return self.application(environ, start_response)
