"""
Couchbase MCP Server
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import click
from mcp.server.fastmcp import FastMCP
import uvicorn

# Import tools
from tools import ALL_TOOLS

# Import middleware
from utils import AVAILABLE_HTTP_MIDDLEWARE_TYPES

# Import utilities
from utils import (
    ALLOWED_TRANSPORTS,
    DEFAULT_HOST,
    DEFAULT_LOG_LEVEL,
    DEFAULT_PORT,
    DEFAULT_READ_ONLY_MODE,
    DEFAULT_TLS_VERIFY,
    DEFAULT_TRANSPORT,
    MCP_SERVER_NAME,
    NETWORK_TRANSPORTS,
    NETWORK_TRANSPORTS_SDK_MAPPING,
    AppContext,
    get_settings,
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, DEFAULT_LOG_LEVEL.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(MCP_SERVER_NAME)

def split_http_middleware_types(ctx, param, value):
    if value is None:
        return None
    if isinstance(value, tuple):
        # If multiple values are already passed via CLI, flatten them
        flat = []
        for v in value:
            flat.extend(v.split(","))
        return tuple(flat)
    return tuple(value.split(","))

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize the MCP server context without establishing database connections."""
    # Get configuration from Click context
    settings = get_settings()
    read_only_query_mode = settings.get("read_only_query_mode", True)

    # Note: We don't validate configuration here to allow tool discovery
    # Configuration will be validated when tools are actually used
    logger.info("MCP server initialized in lazy mode for tool discovery.")
    app_context = None
    try:
        app_context = AppContext(read_only_query_mode=read_only_query_mode)
        yield app_context

    except Exception as e:
        logger.error(f"Error in app lifespan: {e}")
        raise
    finally:
        # Close the cluster connection
        if app_context and app_context.cluster:
            app_context.cluster.close()
        logger.info("Closing MCP server")


@click.command()
@click.option(
    "--connection-string",
    envvar="CB_CONNECTION_STRING",
    help="Couchbase connection string (required for operations)",
)
@click.option(
    "--username",
    envvar="CB_USERNAME",
    help="Couchbase database user (required for operations)",
)
@click.option(
    "--password",
    envvar="CB_PASSWORD",
    help="Couchbase database password (required for operations)",
)
@click.option(
    "--ca-cert-path",
    envvar="CB_CA_CERT_PATH",
    default=None,
    help="Path to the server trust store (CA certificate) file. The certificate at this path is used to verify the server certificate during the authentication process.",
)
@click.option(
    "--client-cert-path",
    envvar="CB_CLIENT_CERT_PATH",
    default=None,
    help="Path to the client certificate file used for mTLS authentication.",
)
@click.option(
    "--client-key-path",
    envvar="CB_CLIENT_KEY_PATH",
    default=None,
    help="Path to the client certificate key file used for mTLS authentication.",
)
@click.option(
    "--tls-verify/--no-tls-verify",
    envvar="CB_TLS_VERIFY",
    default=DEFAULT_TLS_VERIFY,
    help="Enable or disable TLS certificate verification when using couchbases://.",
)
@click.option(
    "--read-only-query-mode",
    envvar=[
        "CB_MCP_READ_ONLY_QUERY_MODE",
        "READ_ONLY_QUERY_MODE",  # Deprecated
    ],
    type=bool,
    default=DEFAULT_READ_ONLY_MODE,
    help="Enable read-only query mode. Set to True (default) to allow only read-only queries. Can be set to False to allow data modification queries.",
)
@click.option(
    "--transport",
    envvar=[
        "CB_MCP_TRANSPORT",
        "MCP_TRANSPORT",  # Deprecated
    ],
    type=click.Choice(ALLOWED_TRANSPORTS),
    default=DEFAULT_TRANSPORT,
    help="Transport mode for the server (stdio, http or sse). Default is stdio",
)
@click.option(
    "--host",
    envvar="CB_MCP_HOST",
    default=DEFAULT_HOST,
    help="Host to run the server on (default: 127.0.0.1)",
)
@click.option(
    "--port",
    envvar="CB_MCP_PORT",
    default=DEFAULT_PORT,
    help="Port to run the server on (default: 8000)",
)
@click.option(
    "--enable-middleware",
    envvar="CB_MCP_ENABLE_MIDDLEWARE",
    is_flag=True,
    default=False,
    help="Enable HTTP middleware.",
)
@click.option(
    "--http-middleware",
    envvar="CB_MCP_HTTP_MIDDLEWARE",
    callback=split_http_middleware_types,
    multiple=True,
    default=None,
    help=(
        "HTTP middleware to enable (e.g., --http-middleware http_logging --http-middleware header_logging). "
        "Env var can be comma-separated: CB_MCP_HTTP_MIDDLEWARE=http_logging,header_logging"
    ),
)

@click.version_option(package_name="couchbase-mcp-server")
@click.pass_context
def main(
    ctx,
    connection_string,
    username,
    password,
    ca_cert_path,
    client_cert_path,
    client_key_path,
    tls_verify,
    read_only_query_mode,
    transport,
    host,
    port,
    enable_middleware,
    http_middleware,
):
    """Couchbase MCP Server"""
    # Store configuration in context
    ctx.obj = {
        "connection_string": connection_string,
        "username": username,
        "password": password,
        "ca_cert_path": ca_cert_path,
        "client_cert_path": client_cert_path,
        "client_key_path": client_key_path,
        "tls_verify": tls_verify,
        "read_only_query_mode": read_only_query_mode,
        "transport": transport,
        "host": host,
        "port": port,
        "enable_middleware": enable_middleware,
        "http_middleware": http_middleware,
    }

    # Map user-friendly transport names to SDK transport names
    sdk_transport = NETWORK_TRANSPORTS_SDK_MAPPING.get(transport, transport)

    # If the transport is network based, we need to pass the host and port to the MCP server
    config = (
        {
            "host": host,
            "port": port,
        }
        if transport in NETWORK_TRANSPORTS
        else {}
    )

    mcp = FastMCP(MCP_SERVER_NAME, lifespan=app_lifespan, **config)

    # Register all tools
    for tool in ALL_TOOLS:
        mcp.add_tool(tool)
        
    if transport == "http":
        mcp_streamable_http_app = mcp.streamable_http_app
        
        if enable_middleware:
            logger.info("HTTP middleware is enabled. Applying HTTP middleware to the server.")
            SELECTED_HTTP_MIDDLEWARE_TYPES = http_middleware
            logger.info(f"Selected HTTP middleware types: {SELECTED_HTTP_MIDDLEWARE_TYPES}")

            for key in SELECTED_HTTP_MIDDLEWARE_TYPES:
                http_middleware_cls = AVAILABLE_HTTP_MIDDLEWARE_TYPES[key]
                mcp_streamable_http_app = http_middleware_cls(mcp_streamable_http_app)
        else:
            logger.info("HTTP middleware is disabled. No HTTP middleware will be applied.")
        
        uvicorn.run(mcp_streamable_http_app, host="0.0.0.0", port=8000, factory=False)
    else:
        mcp.run(transport=sdk_transport)

if __name__ == "__main__":
    main()
