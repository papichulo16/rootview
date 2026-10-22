// Guest pages. Everything read from a guest is untrusted, so it only ever
// reaches the DOM through textContent.

const RootViewGuest = (() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  function detailOf(data) {
    if (!data || data.detail === undefined) return null;
    if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg).join("; ");
    return String(data.detail);
  }

  async function api(method, url, body) {
    const init = { method, headers: {} };
    if (body !== undefined) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const r = await fetch(url, init);
    if (r.status === 204) return null;
    const data = await r.json().catch(() => null);
    if (!r.ok) throw new Error(detailOf(data) || `${r.status} ${r.statusText}`);
    return data;
  }

  function notice(message, isError = true) {
    const n = $("notice");
    if (!n) return;
    n.textContent = message;
    n.classList.toggle("is-error", isError);
    n.hidden = !message;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function row(cells, className) {
    const tr = el("tr", className);
    for (const c of cells) {
      const td = el("td");
      if (c instanceof Node) td.append(c);
      else td.textContent = c;
      tr.append(td);
    }
    return tr;
  }

  function kv(target, pairs) {
    target.replaceChildren();
    for (const [k, v] of pairs) {
      if (v === undefined || v === null || v === "") continue;
      const div = el("div");
      div.append(el("dt", null, k), el("dd", null, String(v)));
      target.append(div);
    }
  }

  function guarded(fn) {
    return async (...args) => {
      try {
        notice("");
        await fn(...args);
      } catch (err) {
        notice(err.message);
      }
    };
  }

  const field = (form, name) => form.elements.namedItem(name);

  function formValues(form) {
    const out = {};
    for (const [k, v] of new FormData(form)) out[k] = String(v).trim();
    return out;
  }

  function lifecycle(vm, action) {
    const name = encodeURIComponent(vm);
    if (action === "destroy") {
      if (!confirm(`Destroy ${vm}? It is stopped if running and its rootview config is deleted; disk images are kept.`)) return false;
      return api("DELETE", `/api/vms/${name}?force=true`);
    }
    return api("POST", `/api/vms/${name}/${action}`);
  }

  function initList() {
    const toggle = document.querySelector('[data-toggle="create-form"]');
    const form = $("create-form");
    if (toggle && form) toggle.addEventListener("click", () => { form.hidden = !form.hidden; });

    form?.addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const v = formValues(form);
      const body = { name: v.name, network: v.network, display: v.display, kvmi_enabled: field(form, "kvmi_enabled").checked };
      for (const k of ["memory_mb", "cpus"]) if (v[k]) body[k] = Number(v[k]);
      for (const k of ["disk_image", "cdrom", "extra_args"]) if (v[k]) body[k] = v[k];
      await api("POST", "/api/vms", body);
      window.location.reload();
    }));

    document.querySelectorAll("[data-action]").forEach((b) => {
      b.addEventListener("click", guarded(async () => {
        b.disabled = true;
        try {
          if ((await lifecycle(b.dataset.vm, b.dataset.action)) !== false) window.location.reload();
        } finally {
          b.disabled = false;
        }
      }));
    });
  }

  function hexdump(addr, hex) {
    const base = BigInt(addr);
    const bytes = hex.match(/../g) || [];
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const ascii = chunk.map((b) => {
        const c = parseInt(b, 16);
        return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
      }).join("");
      const at = (base + BigInt(i)).toString(16).padStart(16, "0");
      lines.push(`${at}  ${chunk.join(" ").padEnd(47)}  ${ascii}`);
    }
    return lines.join("\n");
  }

  function initGuest(vm, introspectable) {
    const base = `/api/vms/${encodeURIComponent(vm)}`;

    document.querySelectorAll("[data-epoch]").forEach((d) => {
      const t = Number(d.dataset.epoch);
      if (t) d.textContent = new Date(t * 1000).toLocaleString();
    });

    document.querySelectorAll("[data-action]").forEach((b) => {
      b.addEventListener("click", guarded(async () => {
        const action = b.dataset.action;
        b.disabled = true;
        try {
          if (["pause", "resume", "profile"].includes(action)) {
            await api("POST", `${base}/${action}`);
            notice(action === "profile" ? "kernel profile rebuilt" : `guest ${action}d`, false);
            if (action === "profile") await loadKernel();
          } else if ((await lifecycle(vm, action)) !== false) {
            window.location.reload();
          }
        } finally {
          b.disabled = false;
        }
      }));
    });

    if (!introspectable) return;

    async function resolveAddr(text) {
      if (/^(0x[0-9a-f]+|\d+)$/i.test(text)) return text;
      const sym = await api("GET", `${base}/symbols/${encodeURIComponent(text)}`);
      return sym.addr;
    }

    async function loadKernel() {
      const target = $("kernel");
      try {
        const k = await api("GET", `${base}/kernel`);
        kv(target, [
          ["Kernel", k.release],
          ["Version", k.version.join(".")],
          ["Image", `${k.image[0]} – ${k.image[1]}`],
          ["Symbols", k.nsyms.toLocaleString()],
          ["BTF types", k.btf_types.toLocaleString()],
          ["BTF found", `${k.btf_va} (${k.btf_by_symbol ? "__start_BTF" : "scan"})`],
          ["init_task", k.init_task],
          ["Banner", k.banner],
        ]);
      } catch (err) {
        kv(target, [["Kernel", `profile unavailable: ${err.message}`]]);
      }
    }

    let tasks = [];
    function renderTasks() {
      const q = $("task-filter").value.trim().toLowerCase();
      const shown = tasks.filter((t) => !q || t.comm.toLowerCase().includes(q) || String(t.pid) === q);
      $("tasks").replaceChildren(...shown.map((t) => row([String(t.pid), String(t.tgid), t.comm, t.addr])));
      $("task-count").textContent = `(${shown.length}${shown.length === tasks.length ? "" : ` of ${tasks.length}`})`;
    }
    async function loadTasks() {
      tasks = await api("GET", `${base}/tasks`);
      renderTasks();
    }

    async function loadRegisters() {
      const regs = await api("GET", `${base}/registers`);
      $("registers").replaceChildren(...Object.entries(regs).map(([k, v]) => {
        const cell = el("div", "reg");
        cell.append(el("span", "reg-name", k), el("code", null, v));
        return cell;
      }));
    }

    function hookTarget(h) {
      if (h.kind === "register") return h.reg;
      if (h.kind === "breakpoint") return h.vaddr;
      if (h.kind === "cpuid") return h.cpuid_leaf ?? "any leaf";
      if (h.kind === "descriptor") return h.descriptor;
      return `gfn ${h.mem_gfn} ${h.access}${h.capture ? " (capture)" : ""}`;
    }
    function renderHooks(hooks) {
      $("hooks").replaceChildren(...hooks.map((h) => {
        const remove = el("button", "btn ghost", "Remove");
        remove.addEventListener("click", guarded(async () => {
          await api("DELETE", `${base}/hooks/${encodeURIComponent(h.name)}`);
          await loadHooks();
        }));
        return row([h.name, h.kind, hookTarget(h), remove]);
      }));
      if (!hooks.length) $("hooks").append(row([el("span", "empty", "No hooks."), "", "", ""]));
    }
    async function loadHooks() {
      renderHooks(await api("GET", `${base}/hooks`));
    }

    function eventDetail(e) {
      if (e.kind === "register") return `${e.old_value} → ${e.new_value}`;
      if (e.kind === "breakpoint") return `hit ${e.vaddr}`;
      if (e.kind === "cpuid") return `leaf ${e.cpuid_leaf} sub ${e.cpuid_subleaf}`;
      if (e.kind === "descriptor") return `${e.descriptor} ${e.desc_is_write ? "write" : "read"}`;
      let s = `${e.mem_access} @ ${e.mem_gpa} rip ${e.rip}`;
      if (e.rip_sym) s += ` (${e.rip_sym}+0x${e.rip_off.toString(16)})`;
      if (e.captured) s += ` ${e.before} → ${e.after}${e.after_ok ? "" : " (no step)"}`;
      return s;
    }
    let dropped = 0;
    let received = 0;
    async function poll() {
      const r = await api("GET", `${base}/hooks/events?timeout_ms=0`);
      dropped += r.dropped;
      received += r.events.length;
      const body = $("events");
      for (const e of r.events) body.prepend(row([String(e.seq), e.name, e.kind, String(e.vcpu), eventDetail(e)]));
      while (body.children.length > 500) body.lastChild.remove();
      $("event-info").textContent = `(${received} received${dropped ? `, ${dropped} dropped` : ""})`;
    }
    let timer = null;
    $("auto-poll").addEventListener("change", (ev) => {
      clearInterval(timer);
      timer = ev.target.checked ? setInterval(async () => {
        try { await poll(); } catch (err) { notice(err.message); ev.target.checked = false; clearInterval(timer); }
      }, 1500) : null;
    });
    $("poll").addEventListener("click", guarded(poll));
    $("clear-events").addEventListener("click", () => {
      $("events").replaceChildren();
      received = dropped = 0;
      $("event-info").textContent = "";
    });

    const loaders = { tasks: loadTasks, registers: loadRegisters, hooks: loadHooks };
    document.querySelectorAll("[data-load]").forEach((b) => b.addEventListener("click", guarded(loaders[b.dataset.load])));
    $("task-filter").addEventListener("input", renderTasks);

    $("mem-form").addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const v = formValues(event.target);
      const addr = await resolveAddr(v.addr);
      const params = new URLSearchParams({ addr, length: v.length, space: v.space });
      const m = await api("GET", `${base}/memory?${params}`);
      $("mem-info").textContent = `${m.data.length / 2} bytes of ${m.space} memory at ${m.addr}`;
      $("hexdump").textContent = hexdump(m.addr, m.data);
    }));

    $("translate").addEventListener("click", guarded(async () => {
      const addr = await resolveAddr(field($("mem-form"), "addr").value.trim());
      const t = await api("GET", `${base}/translate?addr=${encodeURIComponent(addr)}`);
      $("mem-info").textContent = `virtual ${t.va} → physical ${t.pa}`;
    }));

    $("write-form")?.addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const v = formValues(event.target);
      if (!confirm(`Write ${v.data.length / 2} bytes to ${v.space} ${v.addr}?`)) return;
      await api("PUT", `${base}/memory`, { space: v.space, addr: await resolveAddr(v.addr), data: v.data });
      notice("written", false);
    }));

    $("reg-form")?.addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const v = formValues(event.target);
      await api("PUT", `${base}/registers/${encodeURIComponent(v.name)}`, { value: v.value });
      notice(`${v.name} staged; it lands when the guest resumes`, false);
    }));

    $("sym-form").addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const s = await api("GET", `${base}/symbols/${encodeURIComponent(formValues(event.target).name)}`);
      kv($("lookup"), [["Symbol", s.name], ["Address", s.addr], ["Type", s.type]]);
    }));

    $("addr-form").addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const addr = await resolveAddr(formValues(event.target).addr);
      const s = await api("GET", `${base}/symbols?addr=${encodeURIComponent(addr)}`);
      kv($("lookup"), [["Address", addr], ["In", s.offset ? `${s.name}+0x${s.offset.toString(16)}` : s.name], ["Symbol at", s.addr], ["Type", s.type]]);
    }));

    $("field-form").addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const v = formValues(event.target);
      const params = new URLSearchParams({ type: v.type, path: v.path });
      if (v.addr) params.set("addr", await resolveAddr(v.addr));
      const f = await api("GET", `${base}/fields?${params}`);
      kv($("lookup"), [
        ["Field", `${f.type}.${f.path}`],
        ["Offset", `+0x${f.offset.toString(16)}`],
        ["Size", `${f.size} bytes`],
        ["Bits", f.bit_size ? `${f.bit_off}..${f.bit_off + f.bit_size - 1}` : ""],
        ["Kind", f.kind],
        ["Type", f.type_name],
        ["Points to", f.ref_name],
        ["Value", f.value],
        ["Length", f.length],
      ]);
    }));

    const hookForm = $("hook-form");
    function showHookInputs() {
      const kind = field(hookForm, "kind").value;
      hookForm.querySelectorAll("[data-kinds]").forEach((input) => {
        input.hidden = !input.dataset.kinds.split(" ").includes(kind);
      });
    }
    field(hookForm, "kind").addEventListener("change", showHookInputs);
    showHookInputs();
    hookForm.addEventListener("submit", guarded(async (event) => {
      event.preventDefault();
      const v = formValues(hookForm);
      const body = { name: v.name, kind: v.kind };
      if (v.kind === "register") body.reg = v.reg;
      if (v.kind === "breakpoint" || v.kind === "mem") body.addr = await resolveAddr(v.addr);
      if (v.kind === "cpuid") body.leaf = v.leaf || "any";
      if (v.kind === "descriptor") body.table = v.table;
      if (v.kind === "mem") body.access = v.access;
      renderHooks(await api("POST", `${base}/hooks`, body));
    }));

    guarded(() => Promise.all([loadKernel(), loadTasks(), loadRegisters(), loadHooks()]))();
  }

  return { initList, initGuest };
})();
