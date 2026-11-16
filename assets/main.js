const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

document.getElementById("year").textContent = new Date().getFullYear();

// Nav: border on scroll + active section
const nav = document.querySelector(".nav");
const links = [...document.querySelectorAll(".nav-links a")];
const onScroll = () => nav.classList.toggle("scrolled", window.scrollY > 8);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();

const sectionIO = new IntersectionObserver(
  (entries) => entries.forEach((e) => {
    if (!e.isIntersecting) return;
    links.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === `#${e.target.id}`));
  }),
  { rootMargin: "-45% 0px -50% 0px" }
);
document.querySelectorAll("main section[id]").forEach((s) => sectionIO.observe(s));

// Count-up numbers
function countUp(el) {
  const to = Number(el.dataset.to);
  if (reduce) return;
  const start = Date.now(), dur = 1400;
  el.textContent = 0;
  const timer = setInterval(() => {
    const p = Math.min(1, (Date.now() - start) / dur);
    el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
    if (p >= 1) clearInterval(timer);
  }, 40);
}

// Reveal on scroll
const io = new IntersectionObserver(
  (entries) => entries.forEach((e) => {
    if (!e.isIntersecting) return;
    e.target.classList.add("in");
    e.target.querySelectorAll(".count").forEach(countUp);
    io.unobserve(e.target);
  }),
  { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
);
document.querySelectorAll(".reveal").forEach((el, i) => {
  el.style.transitionDelay = `${(i % 4) * 80}ms`;
  io.observe(el);
});

// Case terminal: scenarios + visitor commands
(() => {
  const term = document.getElementById("term");
  const status = document.getElementById("caseStatus");
  const title = document.getElementById("caseTitle");
  const sev = document.getElementById("caseSev");
  const scope = document.getElementById("caseScope");
  const tabs = [...document.querySelectorAll("#caseTabs button")];
  const replay = document.getElementById("caseReplay");
  const form = document.getElementById("caseForm");
  const input = document.getElementById("caseCmd");
  const C = (t) => `<span class="crit">[!]</span> ${t}`, I = (t) => `<span class="warn">[i]</span> ${t}`, K = (t) => `<span class="ok">[✓]</span> ${t}`;
  const scenarios = {
    phishing: { id: "IR-2026-0412", sev: "critical", scope: "3 hosts", lines: [
      ["falcon rtr triage WS-0412", C('winword.exe → <span class="warn">rundll32.exe</span>')],
      ["sandbox submit invoice.docm", C("malicious · C2 185.220.x.x")],
      ["splunk search dest_ip=185.220.*", I("3 hosts · scope confirmed")],
      ["soar run contain_and_block", K("contained · IoCs blocked")],
    ]},
    identity: { id: "IR-2026-0387", sev: "high", scope: "1 account", lines: [
      ["splunk search user=svc_backup action=failure", C("4,812 failed logons · 1 success")],
      ["itdr check svc_backup", C("impossible travel · new device")],
      ["falcon rtr triage SRV-DB02", I("no persistence found")],
      ["soar run disable_and_reset", K("account locked · sessions revoked")],
    ]},
    web: { id: "IR-2026-0455", sev: "high", scope: "2 services", lines: [
      ["waf logs --service api-gw --last 15m", C("SQLi pattern · 2,140 req / 3 IPs")],
      ["splunk search uri=/api/v2/* status=200", I("no data returned · attack blocked")],
      ["waf rule tune --id 94210 --mode block", K("rule tightened")],
      ["soar run block_ioc --feed cti", K("IPs blocked · IoCs shared")],
    ]},
  };
  const order = Object.keys(scenarios);
  const P = '<span class="p">$</span> ', cur = '<span class="cursor"></span>';
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  let run = 0, auto = true, current = "phishing", buf = [];
  const setStatus = (done) => { status.textContent = done ? "contained" : "investigating"; status.classList.toggle("done", done); };
  const paint = (extra) => { term.innerHTML = [...buf, ...(extra ? [extra] : [])].join("\n") + (extra ? "" : cur); term.scrollTop = term.scrollHeight; };

  async function play(name) {
    const my = ++run, sc = scenarios[name];
    current = name;
    tabs.forEach((t) => { const on = t.dataset.s === name; t.classList.toggle("on", on); t.setAttribute("aria-selected", on); });
    title.textContent = `case ${sc.id}`; sev.textContent = sc.sev; sev.className = sc.sev === "critical" ? "sev" : "sev high"; scope.textContent = sc.scope;
    buf = [];
    if (reduce) { buf = sc.lines.flatMap(([c, o]) => [`${P}<span class="cmd">${c}</span>`, o]); paint(); setStatus(true); return; }
    setStatus(false);
    paint();
    await sleep(500);
    for (const [c, o] of sc.lines) {
      for (let i = 0; i <= c.length; i++) {
        if (my !== run) return;
        paint(`${P}<span class="cmd">${c.slice(0, i)}</span>${cur}`);
        await sleep(30);
      }
      await sleep(400); if (my !== run) return;
      buf.push(`${P}<span class="cmd">${c}</span>`, o);
      paint();
      await sleep(650); if (my !== run) return;
    }
    setStatus(true);
    await sleep(6000);
    if (my === run && auto) play(order[(order.indexOf(name) + 1) % order.length]);
  }

  // Visitor commands
  const go = (id) => document.getElementById(id).scrollIntoView({ behavior: reduce ? "auto" : "smooth" });
  const esc = (t) => t.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));
  const dim = (t) => `<span class="dim">${t}</span>`, ok = (t) => `<span class="ok">${t}</span>`;
  const btn = (cmd, label) => `<button type="button" class="tcmd" data-cmd="${cmd}">${label || cmd}</button>`;
  const row = (label, cmds) => `${dim(label.padEnd(9))}${cmds.map((c) => btn(c)).join(" ")}`;
  const print = (...lines) => { buf.push(...lines); if (buf.length > 60) buf = buf.slice(-60); paint(); };
  const steps = async (my, arr) => { for (const [ms, line] of arr) { await sleep(reduce ? 0 : ms); if (my !== run) return false; print(line); } return true; };
  const bar = async (my, label) => {
    buf.push("");
    const at = buf.length - 1;
    for (let i = 0; i <= 16; i++) {
      if (my !== run) return false;
      buf[at] = `${label} ${ok("█".repeat(i))}${dim("░".repeat(16 - i))} ${String(Math.round((i / 16) * 100)).padStart(3)}%`;
      paint();
      await sleep(reduce ? 0 : 70);
    }
    return true;
  };
  const files = {
    "about.md": "Senior Cyber Security Incident Responder\n@ Turkcell Cyber Defense Center · Istanbul\n5+ years on the blue team.",
    "skills.txt": "IR · DFIR · Detection Engineering · SOAR\nThreat Hunting · CTI · AI · Cloud",
    "stack.txt": "SIEM  Splunk · QRadar · ArcSight · Logsign\nEDR   CrowdStrike Falcon · Trend Micro\nNET   WAF · IPS · Suricata · Snort · A10\nINTEL ATT&amp;CK · SOCRadar · Mandiant\nAUTO  SOAR · Python · AI · GCP · AWS\n+ whatever your stack runs",
    "education.txt": "B.Sc. Software Engineering\nKırklareli University · 2018–2022\nranked 3rd · GPA 3.62",
    "contact.txt": "yusufturrgut@gmail.com\nlinkedin.com/in/yusuf-turgut",
  };
  const sections = ["about", "expertise", "experience", "contact"];
  const mitre = [["T1566.001", "Spearphishing Attachment", "Initial Access"], ["T1059.001", "PowerShell", "Execution"], ["T1078", "Valid Accounts", "Persistence"], ["T1190", "Exploit Public-Facing App", "Initial Access"], ["T1021.001", "Remote Desktop Protocol", "Lateral Movement"], ["T1055", "Process Injection", "Defense Evasion"], ["T1003.001", "LSASS Memory", "Credential Access"], ["T1486", "Data Encrypted for Impact", "Impact"], ["T1071.001", "Web Protocols (C2)", "Command & Control"]];
  const hist = []; let hi = 0;

  const commands = {
    help: () => [row("profile", ["whoami", "about", "creed", "scope", "skills", "stack", "experience", "education", "contact"]), row("security", ["scan", "hunt", "mitre", "ioc", "status", "incidents"]), row("shell", ["ls", "cat", "open", "history", "clear"]), dim("tab completes · ↑↓ history · click any command")].join("\n"),
    whoami: () => `Yusuf Turgut\n${ok("Senior Cyber Security Incident Responder")} @ Turkcell`,
    scope: () => `${I("declared scope: incident response")}\n${K("effective scope: wherever the problem is")}`,
    creed: () => `out of scope? ${ok("still my problem.")}\nrespond · hunt · detect · automate · harden · mentor`,
    about: () => files["about.md"],
    skills: () => files["skills.txt"],
    stack: () => files["stack.txt"],
    education: () => files["education.txt"],
    experience: () => { go("experience"); return I("5+ years · opening timeline…"); },
    contact: () => { go("contact"); return `${K("yusufturrgut@gmail.com")}\n${btn("email")} ${btn("linkedin")} ${btn("github")}`; },
    email: () => { location.href = "mailto:yusufturrgut@gmail.com"; return K("opening mail client…"); },
    linkedin: () => { window.open("https://www.linkedin.com/in/yusuf-turgut/", "_blank", "noopener"); return K("opening linkedin…"); },
    github: () => { window.open("https://github.com/yusufturgut", "_blank", "noopener"); return K("opening github…"); },
    ls: () => Object.keys(files).map((f) => btn(`cat ${f}`, f)).join("  "),
    cat: (a) => !a[0] ? `usage: cat &lt;file&gt; — try ${btn("ls")}` : files[a[0]] || `cat: ${esc(a[0])}: no such file — try ${btn("ls")}`,
    open: (a) => { if (!sections.includes(a[0])) return `usage: open ${sections.map((x) => btn(`open ${x}`, x)).join(" | ")}`; go(a[0]); return K(`opening ${a[0]}…`); },
    pwd: () => "/home/visitor",
    date: () => new Date().toUTCString(),
    uptime: () => `blue team uptime: ${ok("5+ years")} · since 07/2021`,
    echo: (a) => esc(a.join(" ")),
    history: () => hist.length ? hist.map((h, i) => `${dim(String(i + 1).padStart(2))}  ${esc(h)}`).join("\n") : dim("empty"),
    status: () => `${ok("●")} monitoring active · tier L2 on duty\n${dim("demo data — not a live feed")}`,
    incidents: () => `${btn("phishing")}  ${dim("IR-2026-0412 · critical")}\n${btn("identity")}  ${dim("IR-2026-0387 · high")}\n${btn("web")}       ${dim("IR-2026-0455 · high")}`,
    mitre: () => { const [id, n, t] = mitre[(Math.random() * mitre.length) | 0]; return `${ok(id)} ${n}\n${dim("tactic: " + t)} · ${btn("mitre", "another")}`; },
    ioc: (a) => !a[0] ? "usage: ioc &lt;ip | domain | hash&gt;" : async (my) => {
      print(I(`looking up ${esc(a[0].slice(0, 32))}`));
      if (!(await bar(my, "feeds  "))) return;
      print(K("no hits · verdict: clean"), dim("demo lookup — nothing was sent anywhere"));
    },
    scan: () => async (my) => {
      print(I("scanning visitor…"));
      if (!(await bar(my, "scan   "))) return;
      await steps(my, [[200, K("no malware found")], [250, K("connection encrypted")], [300, `${I("threat level:")} ${ok("curious")}`]]);
    },
    hunt: () => async (my) => {
      print(I("hypothesis: C2 beaconing over HTTPS"));
      if (!(await bar(my, "splunk "))) return;
      await steps(my, [[250, C("1 host · beacon every 60s ± 2s")], [450, I("falcon: unsigned binary in %TEMP%")], [450, K("confirmed → host isolated")], [350, K("new detection rule created")]]);
    },
    matrix: () => { document.body.classList.toggle("boost"); return K(`network view ${document.body.classList.contains("boost") ? "boosted" : "normal"}`); },
    sudo: () => C("nice try — this incident will be reported."),
    rm: () => C("permission denied — and logged."),
    hack: () => `${C("alert raised · analyst notified")}\n${dim("…just kidding. or not.")}`,
    nmap: () => C("port scan detected from your IP · blocked on WAF"),
    coffee: () => K("☕ refilled · analyst efficiency +20%"),
    exit: () => "there is no exit — only containment.",
  };
  const names = [...Object.keys(commands), ...order, "clear"].sort();

  async function exec(raw) {
    raw = raw.trim();
    if (!raw) return;
    hist.push(raw); if (hist.length > 30) hist.shift(); hi = hist.length;
    const [cmd, ...args] = raw.toLowerCase().split(/\s+/);
    auto = false;
    if (scenarios[cmd]) { play(cmd); return; }
    const my = ++run;
    if (cmd === "clear") { buf = []; paint(); return; }
    print(`${P}<span class="cmd">${esc(raw)}</span>`);
    const fn = commands[cmd];
    const out = fn ? fn(args) : `command not found: ${esc(cmd)} — try ${btn("help")}`;
    if (typeof out === "function") await out(my); else if (out) print(out);
  }

  form.addEventListener("submit", (e) => { e.preventDefault(); const v = input.value; input.value = ""; exec(v); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowUp" && hist.length) { e.preventDefault(); hi = Math.max(0, hi - 1); input.value = hist[hi]; }
    else if (e.key === "ArrowDown") { e.preventDefault(); hi = Math.min(hist.length, hi + 1); input.value = hist[hi] || ""; }
    else if (e.key === "Tab") {
      const v = input.value.trim().toLowerCase();
      if (!v) return;
      e.preventDefault();
      const parts = v.split(/\s+/);
      const pool = parts.length > 1 ? (parts[0] === "cat" ? Object.keys(files) : parts[0] === "open" ? sections : []) : names;
      const last = parts[parts.length - 1];
      const m = pool.filter((n) => n.startsWith(last));
      if (m.length === 1) input.value = [...parts.slice(0, -1), m[0]].join(" ") + (parts.length === 1 && ["cat", "open", "ioc"].includes(m[0]) ? " " : "");
      else if (m.length > 1) { run++; auto = false; print(dim(m.join("  "))); }
    } else if (e.key === "l" && e.ctrlKey) { e.preventDefault(); exec("clear"); }
  });
  document.querySelector(".case").addEventListener("click", (e) => {
    const b = e.target.closest(".tcmd");
    if (b) { exec(b.dataset.cmd); input.focus({ preventScroll: true }); }
  });
  addEventListener("keydown", (e) => {
    if (e.key === "/" && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) { e.preventDefault(); input.focus(); }
  });
  document.querySelector(".case").addEventListener("click", (e) => { if (!e.target.closest("button, a")) input.focus({ preventScroll: true }); });
  tabs.forEach((t) => t.addEventListener("click", () => { auto = false; play(t.dataset.s); }));
  replay.addEventListener("click", () => { auto = false; play(current); });
  setTimeout(() => play("phishing"), reduce ? 0 : 900);
})();

// Capability tiles: tap to flip on touch devices
document.querySelectorAll(".xgrid li").forEach((li) => {
  li.addEventListener("click", () => li.classList.toggle("on"));
  li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); li.classList.toggle("on"); } });
});

// IR lifecycle (click a phase)
(() => {
  const cells = [...document.querySelectorAll("#ir li")];
  const desc = document.getElementById("irDesc");
  const text = [
    "Playbooks, log onboarding and detection use cases — ready before the alert fires.",
    "Splunk detections and Falcon XDR triage to confirm, scope and prioritise the incident.",
    "Isolate hosts, block IoCs on WAF/IPS and stop lateral movement fast.",
    "Remove malware and persistence, and close the root cause.",
    "Bring systems back safely and watch closely for re-compromise.",
    "Turn findings into new detections, SOAR playbooks and threat hunts.",
  ];
  let k = 0, timer;
  const set = (n) => {
    k = n;
    cells.forEach((c, i) => { c.classList.toggle("done", i < n); c.classList.toggle("now", i === n); });
    desc.innerHTML = `<span>phase 0${n + 1} →</span> ${text[n]}`;
  };
  set(0);
  if (!reduce) timer = setInterval(() => set((k + 1) % cells.length), 3200);
  cells.forEach((c, i) => c.querySelector("button").addEventListener("click", () => { clearInterval(timer); set(i); }));
})();

// Stack filter
(() => {
  const btns = [...document.querySelectorAll("#stackFilters button")];
  const chips = [...document.querySelectorAll("#stackChips li[data-c]")];
  btns.forEach((b) => b.addEventListener("click", () => {
    btns.forEach((x) => x.classList.toggle("on", x === b));
    const f = b.dataset.f;
    chips.forEach((c) => c.classList.toggle("off", f !== "all" && c.dataset.c !== f));
  }));
})();

// Rotating tagline
(() => {
  const el = document.getElementById("tagline");
  const lines = ["calm under incident", "out of scope? still my problem", "see it. own it. fix it.", "respond first, everywhere"];
  if (reduce || !el) return;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  (async () => {
    let i = 0;
    await sleep(3500);
    while (true) {
      const cur = lines[i];
      for (let k = cur.length; k >= 0; k--) { el.textContent = cur.slice(0, k); await sleep(22); }
      i = (i + 1) % lines.length;
      const next = lines[i];
      for (let k = 0; k <= next.length; k++) { el.textContent = next.slice(0, k); await sleep(45); }
      await sleep(3200);
    }
  })();
})();

// Career path
(() => {
  const roles = [
    { yr: "2021", lvl: "Intern", when: "07/2021 — 10/2021", title: "Cyber Security Intern", org: "UITSEC Security Technologies · Istanbul", pts: ["SOC and blue-team support, cyber-intelligence research.", "IDS/IPS, monitoring and packet analysis."] },
    { yr: "2021", lvl: "L1 Analyst", when: "10/2021 — 07/2022", title: "Cyber Security Analyst – L1", org: "CyberForce SOC · a UITSEC company", pts: ["L1 monitoring across ArcSight, QRadar, Logsign and CryptoSIM.", "SIEM rule and correlation support for customers."] },
    { yr: "2022", lvl: "Analyst", when: "07/2022 — 01/2023", title: "Cyber Security Analyst", org: "ING Türkiye · via Mirsis", pts: ["Blue-team analyst in the bank's Cyber Defense Center.", "Phishing analysis, blocking and DDoS tracking."] },
    { yr: "2023", lvl: "Analyst", when: "01/2023 — 07/2024", title: "Cyber Security Analyst", org: "Turkcell · Istanbul", pts: ["Monitoring across EDR, firewall, IPS, DLP and WAF.", "Threat-intel reporting and automations for the BOZOK TI Platform."] },
    { yr: "2024", lvl: "Senior Analyst", when: "07/2024 — 03/2025", title: "Senior Cyber Security Analyst", org: "Turkcell · Istanbul", pts: ["Bridged DFIR, planning and analyst teams.", "Tuned SIEM detections, built SOAR playbooks and Python automations."] },
    { yr: "2025", lvl: "Senior IR", when: "03/2025 — now", title: "Senior Cyber Security Incident Responder", org: "Turkcell · Istanbul", pts: ["L2 escalation point: end-to-end incident response and DFIR.", "Splunk detections, SOAR playbooks and log integrations.", "Threat hunting, AI-assisted automation, mentoring."] },
  ];
  const wrap = document.getElementById("pathSteps");
  const detail = document.getElementById("pathDetail");
  const $ = (id) => document.getElementById(id);
  const btns = roles.map((r, i) => {
    const b = document.createElement("button");
    b.type = "button"; b.className = "step"; b.setAttribute("role", "tab");
    b.style.setProperty("--h", `${26 + i * 20}px`);
    b.innerHTML = `<span class="bar"></span><span class="yr">${r.yr}</span><span class="lvl">${r.lvl}</span>`;
    b.addEventListener("click", () => select(i));
    wrap.append(b);
    return b;
  });
  function select(i) {
    const r = roles[i];
    btns.forEach((b, k) => { b.classList.toggle("on", k === i); b.classList.toggle("past", k < i); b.setAttribute("aria-selected", k === i); b.tabIndex = k === i ? 0 : -1; });
    $("pdWhen").textContent = r.when; $("pdTitle").textContent = r.title; $("pdOrg").textContent = r.org;
    $("pdRef").hidden = i !== roles.length - 1;
    $("pdPoints").replaceChildren(...r.pts.map((t) => { const li = document.createElement("li"); li.textContent = t; return li; }));
    detail.classList.remove("swap"); void detail.offsetWidth; detail.classList.add("swap");
  }
  wrap.addEventListener("keydown", (e) => {
    const cur = btns.findIndex((b) => b.classList.contains("on"));
    const n = e.key === "ArrowRight" ? cur + 1 : e.key === "ArrowLeft" ? cur - 1 : -1;
    if (n >= 0 && n < btns.length) { e.preventDefault(); select(n); btns[n].focus(); }
  });
  select(roles.length - 1);
})();

// Card spotlight
document.querySelectorAll(".xgrid li").forEach((el) => {
  el.addEventListener("pointermove", (e) => {
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  });
});

// Network background
(() => {
  const cv = document.getElementById("net");
  if (!cv) return;
  const ctx = cv.getContext("2d");
  const DPR = Math.min(window.devicePixelRatio || 1, 2);
  let w, h, nodes, packets = [], mouse = null;
  addEventListener("pointermove", (e) => { mouse = { x: e.clientX * DPR, y: e.clientY * DPR }; }, { passive: true });
  addEventListener("pointerleave", () => { mouse = null; });
  function init() {
    w = cv.width = innerWidth * DPR; h = cv.height = innerHeight * DPR;
    const count = Math.round(Math.min(60, (innerWidth * innerHeight) / 24000));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.16 * DPR, vy: (Math.random() - 0.5) * 0.16 * DPR,
      threat: Math.random() < 0.06,
    }));
  }
  function frame() {
    ctx.clearRect(0, 0, w, h);
    const L = 150 * DPR, links = [];
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j], d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < L) {
          links.push([a, b]);
          ctx.strokeStyle = `rgba(0,255,156,${0.12 * (1 - d / L)})`;
          ctx.lineWidth = DPR;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
    }
    if (mouse) {
      for (const n of nodes) {
        const d = Math.hypot(n.x - mouse.x, n.y - mouse.y), M = 190 * DPR;
        if (d < M) {
          ctx.strokeStyle = `rgba(0,255,156,${0.35 * (1 - d / M)})`;
          ctx.lineWidth = DPR;
          ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
        }
      }
    }
    for (const n of nodes) {
      if (!reduce) { n.x += n.vx; n.y += n.vy; }
      if (n.x < 0 || n.x > w) n.vx *= -1;
      if (n.y < 0 || n.y > h) n.vy *= -1;
      ctx.fillStyle = n.threat ? "rgba(244,63,94,.85)" : "rgba(0,255,156,.6)";
      ctx.beginPath(); ctx.arc(n.x, n.y, (n.threat ? 2.4 : 1.6) * DPR, 0, Math.PI * 2); ctx.fill();
    }
    if (!reduce && links.length && Math.random() < 0.07 && packets.length < 12) {
      const [a, b] = links[(Math.random() * links.length) | 0];
      packets.push({ a, b, t: 0 });
    }
    packets = packets.filter((p) => (p.t += 0.02) < 1);
    for (const p of packets) {
      ctx.fillStyle = "rgba(34,211,238,.95)";
      ctx.beginPath(); ctx.arc(p.a.x + (p.b.x - p.a.x) * p.t, p.a.y + (p.b.y - p.a.y) * p.t, 1.8 * DPR, 0, Math.PI * 2); ctx.fill();
    }
    if (!reduce) requestAnimationFrame(frame);
  }
  init(); frame();
  addEventListener("resize", () => { init(); if (reduce) frame(); });
})();
