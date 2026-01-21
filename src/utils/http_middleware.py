from typing import Callable
from starlette.types import Receive, Scope, Send

from starlette.types import Receive, Scope, Send
from typing import Callable, Union

ASGIApp = Callable[[Scope, Receive, Send], "Coroutine"]

class BaseMiddleware:
    """
    Middleware wrapper that works with either:
      - an ASGI app instance
      - a factory callable that returns an ASGI app instance
    """

    def __init__(self, app_or_factory: Union[ASGIApp, Callable[[], ASGIApp]]):
        # If app_or_factory takes 3 arguments, treat as ASGI app
        # Otherwise, treat as a factory
        try:
            import inspect
            sig = inspect.signature(app_or_factory)
            if len(sig.parameters) == 3:
                # Already ASGI app
                self._asgi_app = app_or_factory
                self._factory = None
            else:
                # Factory
                self._asgi_app = None
                self._factory = app_or_factory
        except Exception:
            # Fallback: treat as factory
            self._asgi_app = None
            self._factory = app_or_factory

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if self._asgi_app is None:
            # Lazily create ASGI app from factory
            self._asgi_app = self._factory()
        await self._asgi_app(scope, receive, send)
        
class HTTPPathAndMethodLoggingMiddleware(BaseMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            print(f"[HTTPPathAndMethodLoggingMiddleware] Path: {scope['path']} - Method: {scope['method']}")
        await super().__call__(scope, receive, send)


class HeaderLoggingMiddleware(BaseMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
            print(f"[HeaderLoggingMiddleware] Headers: {headers}")
        await super().__call__(scope, receive, send)
