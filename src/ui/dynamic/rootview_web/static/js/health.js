// Health page: keeps each guest's scan status current from the event stream.

(() => {
  "use strict";

  const table = document.getElementById("health-guests");
  if (!table) {
    RootView.connect({});
    return;
  }

  const staleAfter = Number(table.dataset.interval) * 3000;
  const rowOf = (vmId) => table.querySelector(`tr[data-vm="${CSS.escape(vmId)}"]`);
  const cell = (row, role) => row.querySelector(`[data-role="${role}"]`);

  function age(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
  }

  function tick() {
    for (const time of table.querySelectorAll("time[data-at]")) {
      const ms = Date.now() - Date.parse(time.dataset.at);
      time.textContent = age(ms);
      time.classList.toggle("stale", ms > staleAfter);
    }
  }

  function setStatus(row, ok, detail) {
    const target = cell(row, "status");
    const pill = document.createElement("span");
    pill.className = ok ? "pill state-running" : "pill warn-pill";
    pill.textContent = ok ? "ok" : "could not be scanned";
    target.replaceChildren(pill);
    if (detail) {
      const note = document.createElement("div");
      note.className = "detail";
      note.textContent = detail;
      target.append(note);
    }
  }

  async function loadKernel(row) {
    const target = cell(row, "kernel");
    try {
      const response = await fetch(`/api/vms/${encodeURIComponent(row.dataset.vm)}/kernel`);
      if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || response.status);
      const k = await response.json();
      target.textContent = `${k.btf_types.toLocaleString()} / ${k.nsyms.toLocaleString()}`;
      target.title = k.banner;
    } catch (err) {
      target.textContent = "unavailable";
      target.title = String(err.message || err);
    }
  }

  RootView.connect({
    scan(s) {
      const row = rowOf(s.vm_id);
      if (!row) return;
      const last = cell(row, "last");
      last.dataset.at = s.finished_at;
      last.classList.remove("muted");
      cell(row, "duration").textContent = `${s.duration_ms} ms`;
      cell(row, "counts").textContent = `${s.programs_examined} / ${s.maps_examined}`;
      cell(row, "findings").textContent = s.detection_count;
      setStatus(row, true);
      tick();
    },

    status(s) {
      const row = s.vm_id && s.level === "error" ? rowOf(s.vm_id) : null;
      if (row) setStatus(row, false, s.message);
    },
  });

  if (table.dataset.kernel === "true") {
    for (const row of table.querySelectorAll('tr[data-running="true"]')) loadKernel(row);
  }
  tick();
  setInterval(tick, 1000);
})();
