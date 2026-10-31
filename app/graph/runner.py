"""Graph runner: opens the PostgresSaver when configured, otherwise runs without checkpoints."""

import os
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@asynccontextmanager
async def checkpointer_runtime():
    """Yield ``(saver, available)``. Never raises: a broken DSN degrades to no checkpointing."""
    database_url = os.getenv("DATABASE_URL_SESSION", "").strip()
    if not database_url:
        yield None, False
        return
    stack = AsyncExitStack()
    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        parts = urlsplit(database_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query["options"] = "-c search_path=langgraph"
        conn_string = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
        saver = await stack.enter_async_context(AsyncPostgresSaver.from_conn_string(conn_string))
        await saver.setup()
    except Exception:
        await stack.aclose()
        yield None, False
        return
    try:
        yield saver, True
    finally:
        await stack.aclose()


async def run_graph(build, state: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Compile the graph with the best available checkpointer and run one scan."""
    async with checkpointer_runtime() as (saver, available):
        graph = build(saver)
        merged = dict(state)
        merged["checkpointer_unavailable"] = not available
        config = {"configurable": {"thread_id": scan_id}} if saver else None
        if config:
            return await graph.ainvoke(merged, config)
        return await graph.ainvoke(merged)


def merge_checkpoint_flag(checks_unavailable: list[str], state: dict[str, Any]) -> None:
    if state.get("checkpointer_unavailable") and "langgraph_checkpointer" not in checks_unavailable:
        checks_unavailable.append("langgraph_checkpointer")
