import asyncio
import logging

logger = logging.getLogger(__name__)


async def fetch_smtp_banner(mx_host: str, timeout: float = 10.0) -> dict[str, str]:
    """Connect to mx_host:25, read banner + EHLO response, QUIT.

    Returns {"banner": "...", "ehlo": "..."} or empty strings on failure.
    """
    banner = ""
    ehlo = ""
    reader = None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx_host, 25), timeout=timeout
        )

        # Read 220 banner
        banner_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        banner = banner_line.decode("utf-8", errors="replace").strip()

        # Send EHLO
        writer.write(b"EHLO mxmap.pt\r\n")
        await writer.drain()

        # Read multi-line EHLO response (250-... continues, 250 ... ends)
        ehlo_lines = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            decoded = line.decode("utf-8", errors="replace").strip()
            ehlo_lines.append(decoded)
            # SMTP multi-line: "250-..." continues, "250 ..." is last line
            if decoded[:4] != "250-":
                break
        ehlo = "\n".join(ehlo_lines)

        # Send QUIT
        writer.write(b"QUIT\r\n")
        await writer.drain()
        # Read QUIT response but don't fail if it doesn't come
        try:
            await asyncio.wait_for(reader.readline(), timeout=2.0)
        except Exception:
            pass

    except Exception as e:
        logger.debug("SMTP banner fetch failed for %s: %s", mx_host, e)
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return {"banner": banner, "ehlo": ehlo}
