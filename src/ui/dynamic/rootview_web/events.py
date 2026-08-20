"""In-process fan-out of live events to connected browsers.

The scanner produces events; every open browser tab consumes them over Server-
Sent Events. SSE rather than WebSockets because the traffic is one-directional
-- the page never pushes back -- and SSE reconnects on its own, which matters
for a dashboard someone leaves open.

Everything here is in-memory and single-process. If RootView ever needs to run
more than one web worker, this is the piece that has to move to a shared broker.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections import deque
from typing import Any, AsyncIterator

from rootview_web.schemas import Detection, ScanResult

#: Events kept for replay to a page that has just loaded.
HISTORY_LIMIT = 200

#: Per-subscriber queue depth. A browser that stops reading (backgrounded tab,
#: dead connection) drops events past this rather than growing without bound.
#: Larger than HISTORY_LIMIT so a fresh subscriber's replay always fits.
QUEUE_LIMIT = 256


class Event(dict):
    """A single message on the bus.

    A plain dict so it serializes directly; the ``type`` key tells the frontend
    which handler to run.
    """

    @classmethod
    def detection(cls, detection: Detection) -> "Event":
        return cls(type="detection", data=detection.model_dump(mode="json"))

    @classmethod
    def scan(cls, result: ScanResult) -> "Event":
        """A completed scan pass, without the detections themselves.

        Detections travel as their own events so the frontend has one code path
        for handling them; this event just updates counters and timestamps.
        """
        return cls(
            type="scan",
            data={
                "vm_id": result.vm_id,
                "finished_at": result.finished_at.isoformat(),
                "programs_examined": result.programs_examined,
                "maps_examined": result.maps_examined,
                "detection_count": len(result.detections),
                "errors": result.errors,
            },
        )

    @classmethod
    def status(cls, message: str, **extra: Any) -> "Event":
        return cls(type="status", data={"message": message, **extra})


class EventBus:
    """Fan-out from the scanner to every connected page."""

    def __init__(self, history_limit: int = HISTORY_LIMIT) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._history: deque[Event] = deque(maxlen=history_limit)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def history(self) -> list[Event]:
        """Events from the recent past, oldest first."""
        return list(self._history)

    def publish(self, event: Event) -> None:
        """Broadcast an event. Never blocks and never raises.

        A slow subscriber loses the event rather than stalling the scanner --
        detection has to keep running even if a browser tab is wedged.
        """
        self._history.append(event)
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    @contextlib.asynccontextmanager
    async def subscribe(self, replay: bool = True) -> AsyncIterator[asyncio.Queue[Event]]:
        """Hand out a queue that receives every event published while open.

        A queue rather than an async generator because the SSE route needs to
        wait on it with a timeout to emit keepalives; cancelling a generator's
        ``__anext__`` would tear the subscription down instead.

        With ``replay``, recent history is pre-loaded so a page that just
        connected is not blank until the next scan completes.
        """
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=QUEUE_LIMIT)
        if replay:
            for past in self.history():
                try:
                    queue.put_nowait(past)
                except asyncio.QueueFull:
                    break
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)

    async def stream(self, replay: bool = True) -> AsyncIterator[Event]:
        """Yield events until the consumer stops iterating.

        Convenience wrapper over :meth:`subscribe` for callers that do not need
        keepalives -- mainly tests.
        """
        async with self.subscribe(replay=replay) as queue:
            while True:
                yield await queue.get()


def format_sse(event: Event) -> str:
    """Encode an event in the Server-Sent Events wire format.

    The event name goes in the ``event:`` field so the frontend can register a
    listener per type instead of switching on the payload.
    """
    payload = json.dumps(event.get("data", {}))
    return f"event: {event.get('type', 'message')}\ndata: {payload}\n\n"


#: Seconds of silence before the stream emits a comment line. Without this,
#: idle SSE connections get closed by proxies and by some browsers.
KEEPALIVE_INTERVAL = 15.0


async def sse_source(
    bus: EventBus,
    keepalive: float = KEEPALIVE_INTERVAL,
    replay: bool = True,
) -> AsyncIterator[str]:
    """Yield an endless SSE body for one connected browser.

    Lives here rather than inline in the route so it can be tested directly --
    driving an infinite stream through a test HTTP client is awkward to shut
    down cleanly.
    """
    async with bus.subscribe(replay=replay) as queue:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=keepalive)
            except asyncio.TimeoutError:
                # SSE comment line: ignored by EventSource, but enough traffic
                # to keep intermediaries from dropping the connection.
                yield ": keepalive\n\n"
                continue
            yield format_sse(event)
