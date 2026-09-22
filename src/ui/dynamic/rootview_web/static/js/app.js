/* RootView frontend.
 *
 * Pages render their initial state on the server, then this script keeps them
 * current from the /api/stream event source. No framework: the amount of DOM
 * that actually changes is small, and a build step would be one more dependency
 * to install wherever this runs.
 */

const RootView = (() => {
  "use strict";

  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  /** Track findings by id so a redelivered event never renders twice.
   *  The server suppresses repeats too, but a page that reconnects gets the
   *  replay buffer again, so the client has to be idempotent as well. */
  const seen = new Set();

  function connIndicator(state, label) {
    const el = document.getElementById("conn");
    if (!el) return;
    el.dataset.state = state;
    el.querySelector(".conn-label").textContent = label;
  }

  /** Open the SSE stream and dispatch to per-type handlers. */
  function connect(handlers) {
    const source = new EventSource("/api/stream");

    source.onopen = () => connIndicator("live", "live");
    source.onerror = () => {
      // EventSource retries on its own; the indicator just has to stop
      // claiming the page is current in the meantime.
      connIndicator("down", "reconnecting");
    };

    Object.entries(handlers).forEach(([type, handler]) => {
      source.addEventListener(type, (event) => {
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch (err) {
          console.error("malformed event payload", err);
          return;
        }
        handler(payload);
      });
    });

    return source;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function formatTime(iso) {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString([], { hour12: false });
  }

  /** Build a finding card. Mirrors the server-side markup in dashboard.html so
   *  a live-arriving finding is indistinguishable from one rendered on load. */
  function renderFinding(d) {
    const card = el("article", `finding sev-${d.severity} new`);
    card.dataset.id = d.detection_id;

    const head = el("div", "finding-head");
    head.append(el("span", "sev-badge", d.severity));
    head.append(el("h3", null, d.title));
    const time = el("time", null, formatTime(d.timestamp));
    head.append(time);
    card.append(head);

    card.append(el("p", null, d.description));

    if (d.recommendation) {
      const reco = el("p", "reco");
      reco.append(el("strong", null, "What to do: "));
      reco.append(document.createTextNode(d.recommendation));
      card.append(reco);
    }

    const evidence = d.evidence || {};
    if (Object.keys(evidence).length > 0) {
      const details = el("details");
      details.append(el("summary", null, "Evidence"));
      const table = el("table", "evidence");
      for (const [key, value] of Object.entries(evidence)) {
        const row = el("tr");
        row.append(el("th", null, key));
        row.append(el("td", null, value === null ? "-" : String(value)));
        table.append(row);
      }
      details.append(table);
      card.append(details);
    }
    return card;
  }

  /** Insert a finding in severity order, most urgent at the top. */
  function insertBySeverity(container, card, severity) {
    const rank = SEVERITY_RANK[severity] ?? 5;
    for (const existing of container.children) {
      const existingSeverity = [...existing.classList]
        .find((c) => c.startsWith("sev-"))
        ?.slice(4);
      if ((SEVERITY_RANK[existingSeverity] ?? 5) > rank) {
        container.insertBefore(card, existing);
        return;
      }
    }
    container.append(card);
  }

  function initDashboard() {
    const findings = document.getElementById("findings");
    const empty = document.getElementById("findings-empty");
    const countLabel = document.getElementById("finding-count");
    const verdict = document.getElementById("verdict");
    const title = document.getElementById("verdict-title");
    const sub = document.getElementById("verdict-sub");

    // Server-rendered findings are already on the page; record them so the
    // replay buffer does not duplicate them.
    for (const node of findings.children) seen.add(node.dataset.id);

    function updateVerdict() {
      const count = findings.children.length;
      countLabel.textContent = `(${count})`;
      empty.hidden = count > 0;
      if (count === 0) return;

      verdict.dataset.state = "alert";
      title.textContent = `${count} finding${count === 1 ? "" : "s"} need attention`;
      sub.textContent =
        "RootView found eBPF activity in a guest that does not look legitimate.";
    }

    /* Promote "waiting for the first scan" to an all-clear, but only on the
     * evidence of a completed scan. A scan event is that evidence; nothing
     * else in this file is allowed to set the clear state. */
    function markScanned() {
      if (verdict.dataset.state !== "pending") return;
      if (findings.children.length > 0) return;
      verdict.dataset.state = "clear";
      title.textContent = "No suspicious eBPF activity detected";
      sub.textContent = "RootView is watching this system from the hypervisor.";
    }

    connect({
      detection(d) {
        if (seen.has(d.detection_id)) return;
        seen.add(d.detection_id);
        insertBySeverity(findings, renderFinding(d), d.severity);
        updateVerdict();

        const card = document.querySelector(`.vm-card[data-vm="${d.vm_id}"]`);
        if (card) {
          card.classList.remove("flash");
          // Reading offsetWidth restarts the CSS animation; without it a
          // second finding on the same guest would not flash again.
          void card.offsetWidth;
          card.classList.add("flash");
        }
      },

      scan(s) {
        markScanned();
        const card = document.querySelector(`.vm-card[data-vm="${s.vm_id}"]`);
        if (!card) return;
        card.querySelector('[data-role="progs"]').textContent = s.programs_examined;
        card.querySelector('[data-role="maps"]').textContent = s.maps_examined;
      },

      status(s) {
        console.warn("rootview status:", s.message);
      },
    });
  }

  function initIntrospect(vmId) {
    // The tables are a point-in-time snapshot rendered server-side. Rather
    // than patching rows live, the page reloads when a scan of the guest being
    // viewed reports something new, so what is on screen is always one
    // coherent snapshot rather than a mix of two.
    let lastCount = null;
    connect({
      scan(s) {
        if (vmId !== null && s.vm_id !== vmId) return;
        if (lastCount !== null && s.detection_count !== lastCount) {
          window.location.reload();
        }
        lastCount = s.detection_count;
      },
      status(s) {
        console.warn("rootview status:", s.message);
      },
    });
  }

  return { initDashboard, initIntrospect, connect };
})();
