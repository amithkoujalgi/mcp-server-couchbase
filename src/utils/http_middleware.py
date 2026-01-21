from typing import Callable
import time
from typing import Callable, Union
import logging
from starlette.types import Receive, Scope, Send
from utils.constants import MCP_SERVER_NAME

ASGIApp = Callable[[Scope, Receive, Send], "Coroutine"]

logger = logging.getLogger(MCP_SERVER_NAME)

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
        
class HTTPRequestLoggingMiddleware(BaseMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            logger.info(f"[HTTPRequestLoggingMiddleware] Request Received: {scope}")
        await super().__call__(scope, receive, send)


class HeaderLoggingMiddleware(BaseMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
            logger.info(f"[HeaderLoggingMiddleware] Headers: {headers}")
        await super().__call__(scope, receive, send)
        
class TimingMiddleware(BaseMiddleware):
    """
    Logs the time taken to process each HTTP request.
    """
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await super().__call__(scope, receive, send)
            return
        start = time.time()
        await super().__call__(scope, receive, send)
        duration = (time.time() - start) * 1000
        logger.info(f"[TimingMiddleware] Path: {scope.get('path')} handled in {duration:.2f} ms")