"""Tests for the event bus and the scanning loop.

Written with ``asyncio.run`` rather than an async test plugin to keep the dev
dependency list to pytest and httpx.
"""

from __future__ import annotations

import asyncio

from rootview_web.events import Event, EventBus, format_sse, sse_source
from rootview_web.services import ScannerService
from tests.conftest import FakeBackend, compromised_snapshot


def test_format_sse_encodes_type_and_payload():
    wire = format_sse(Event.status("hello", level="info"))
    assert wire.startswith("event: status\n")
    assert '"message": "hello"' in wire
    assert wire.endswith("\n\n")


def test_publish_reaches_subscriber():
    async def scenario():
        bus = EventBus()
        async with bus.subscribe() as queue:
            bus.publish(Event.status("ping"))
            return await asyncio.wait_for(queue.get(), timeout=1)

    event = asyncio.run(scenario())
    assert event["data"]["message"] == "ping"


def test_subscriber_receives_replayed_history():
    async def scenario():
        bus = EventBus()
        bus.publish(Event.status("earlier"))
        async with bus.subscribe(replay=True) as queue:
            return await asyncio.wait_for(queue.get(), timeout=1)

    assert asyncio.run(scenario())["data"]["message"] == "earlier"


def test_subscriber_is_removed_after_use():
    async def scenario():
        bus = EventBus()
        async with bus.subscribe():
            inside = bus.subscriber_count
        return inside, bus.subscriber_count

    assert asyncio.run(scenario()) == (1, 0)


def test_slow_subscriber_does_not_block_publisher():
    """A wedged browser tab must not stall detection."""

    async def scenario():
        bus = EventBus()
        async with bus.subscribe(replay=False) as queue:
            overflow = queue.maxsize + 50
            for i in range(overflow):
                bus.publish(Event.status(f"event {i}"))
            return queue.maxsize, queue.qsize()

    maxsize, qsize = asyncio.run(scenario())
    # Publishing returned rather than blocking, and the queue stopped at its
    # bound instead of growing without limit.
    assert qsize == maxsize


def test_sse_source_emits_events_then_keepalives():
    async def scenario():
        bus = EventBus()
        bus.publish(Event.status("first"))
        source = sse_source(bus, keepalive=0.05)
        try:
            replayed = await anext(source)
            marker = await anext(source)
            idle = await anext(source)
            return replayed, marker, idle
        finally:
            await source.aclose()

    replayed, marker, idle = asyncio.run(scenario())
    assert replayed.startswith("event: status\n")
    assert marker.startswith("event: ready\n")
    assert idle == ": keepalive\n\n"


def test_ready_marker_separates_history_from_live_events():
    """The marker must land after everything replayed and before anything new.

    The introspect page reloads itself when a scan reports a different finding
    count, and only events after this marker are allowed to trigger that. If
    the marker arrived early, replayed history would read as live news, the
    page would reload, reconnect, be replayed the same history, and reload
    again without end.
    """

    async def scenario():
        bus = EventBus()
        bus.publish(Event.status("before one"))
        bus.publish(Event.status("before two"))

        source = sse_source(bus, keepalive=5)
        try:
            first = await anext(source)
            second = await anext(source)
            marker = await anext(source)
            bus.publish(Event.status("after"))
            live = await anext(source)
            return first, second, marker, live
        finally:
            await source.aclose()

    first, second, marker, live = asyncio.run(scenario())
    assert "before one" in first
    assert "before two" in second
    assert marker.startswith("event: ready\n")
    assert "after" in live


def test_ready_marker_is_sent_even_with_no_history():
    """A page connecting to an idle server still needs to know it is live."""

    async def scenario():
        source = sse_source(EventBus(), keepalive=5)
        try:
            return await anext(source)
        finally:
            await source.aclose()

    assert asyncio.run(scenario()).startswith("event: ready\n")


def test_sse_source_unsubscribes_when_closed():
    """A disconnected browser must not leave its queue on the bus."""

    async def scenario():
        bus = EventBus()
        source = sse_source(bus, keepalive=0.05)
        await anext(source)  # subscribes, then times out into a keepalive
        during = bus.subscriber_count
        await source.aclose()
        return during, bus.subscriber_count

    assert asyncio.run(scenario()) == (1, 0)


def test_history_is_capped():
    bus = EventBus(history_limit=5)
    for i in range(20):
        bus.publish(Event.status(str(i)))
    history = bus.history()
    assert len(history) == 5
    assert history[-1]["data"]["message"] == "19"


def test_scanner_publishes_each_finding_once():
    """A standing finding must not re-alert on every polling pass."""

    async def scenario():
        backend = FakeBackend(compromised_snapshot())
        bus = EventBus()
        scanner = ScannerService(backend, bus, interval=0.01)
        await scanner.scan_once()
        first = [e for e in bus.history() if e["type"] == "detection"]
        await scanner.scan_once()
        total = [e for e in bus.history() if e["type"] == "detection"]
        return len(first), len(total)

    first, total = asyncio.run(scenario())
    assert first > 0
    assert first == total


def test_scanner_skips_non_running_guests():
    async def scenario():
        backend = FakeBackend(compromised_snapshot())
        bus = EventBus()
        scanner = ScannerService(backend, bus, interval=0.01)
        results = await scanner.scan_once()
        return {r.vm_id for r in results}

    assert asyncio.run(scenario()) == {"vm-1"}


def test_scanner_forget_allows_realerting():
    async def scenario():
        backend = FakeBackend(compromised_snapshot())
        bus = EventBus()
        scanner = ScannerService(backend, bus, interval=0.01)
        await scanner.scan_once()
        before = len([e for e in bus.history() if e["type"] == "detection"])
        scanner.forget()
        await scanner.scan_once()
        after = len([e for e in bus.history() if e["type"] == "detection"])
        return before, after

    before, after = asyncio.run(scenario())
    assert after == before * 2
