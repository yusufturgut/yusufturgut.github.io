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

// Case terminal
(() => {
  const term = document.getElementById("term");
  const status = document.getElementById("caseStatus");
  const P = '<span class="p">$</span> ';
  const lines = [
    ["falcon rtr triage WS-0412", '<span class="crit">[!]</span> winword.exe → <span class="warn">rundll32.exe</span>'],
    ["sandbox submit invoice.docm", '<span class="crit">[!]</span> malicious · C2 185.220.x.x'],
    ["splunk search dest_ip=185.220.*", '<span class="warn">[i]</span> 3 hosts · scope confirmed'],
    ["soar run contain_and_block", '<span class="ok">[✓]</span> contained · IoCs blocked'],
  ];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const cur = '<span class="cursor"></span>';
  const setStatus = (done) => { status.textContent = done ? "contained" : "investigating"; status.classList.toggle("done", done); };
  if (reduce) {
    term.innerHTML = lines.map(([c, o]) => `${P}<span class="cmd">${c}</span>\n${o}`).join("\n");
    setStatus(true); return;
  }
  (async () => {
    await sleep(1200);
    while (true) {
      setStatus(false);
      const done = [];
      for (const [c, o] of lines) {
        for (let i = 0; i <= c.length; i++) {
          term.innerHTML = [...done, `${P}<span class="cmd">${c.slice(0, i)}</span>${cur}`].join("\n");
          await sleep(38);
        }
        await sleep(450);
        done.push(`${P}<span class="cmd">${c}</span>`, o);
        term.innerHTML = done.join("\n") + cur;
        await sleep(750);
      }
      setStatus(true);
      await sleep(6000);
    }
  })();
})();

// IR lifecycle
(() => {
  const cells = [...document.querySelectorAll("#ir li")];
  const set = (k) => cells.forEach((c, i) => { c.classList.toggle("done", i < k); c.classList.toggle("now", i === k); });
  if (reduce) { set(cells.length); return; }
  let k = 0;
  set(0);
  setInterval(() => { k = (k + 1) % (cells.length + 1); set(k); }, 1600);
})();

// Network background
(() => {
  const cv = document.getElementById("net");
  if (!cv) return;
  const ctx = cv.getContext("2d");
  const DPR = Math.min(window.devicePixelRatio || 1, 2);
  let w, h, nodes, packets = [];
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
