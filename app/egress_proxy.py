import asyncio
import os

from .pinned_proxy import PinnedEgressProxy, egress_token


async def main():
    token = os.getenv("BROWSER_SERVICE_KEY", "")
    if not token:
        raise RuntimeError("SERVICE_API_KEY is required")
    proxy = PinnedEgressProxy("0.0.0.0", 8888, egress_token(token))
    async with proxy:
        await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
