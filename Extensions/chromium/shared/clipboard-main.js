// Runs in the page's MAIN world at document_start. Wraps the programmatic clipboard APIs so the
// isolated-world content script can screen what the page tries to put on the clipboard. The page
// sees a Promise that resolves once RamPart (or the user) allows the write.
//
// N4 (harden-hx6): decisions no longer travel over window.postMessage, which any page script can
// forge. The isolated-world bridge (shared/clipboard-bridge.js, also document_start) creates a
// MessageChannel and hands us one port in a single window message. That message is posted before
// any page script has run, so it is the first one in the queue; we accept exactly one handshake,
// hide it from page listeners (our capture listener was registered first), and from then on only
// listen on the private port. Every port message also carries the bridge's nonce.
(() => {
  if (window.__rampartClipboardHooked) return;
  try { Object.defineProperty(window, "__rampartClipboardHooked", { value: true, configurable: false, writable: false, enumerable: false }); } catch { return; }

  const NONCE_RE = /^[0-9a-f]{32}$/;
  let port = null, nonce = null;
  let seq = 0;
  const waiting = new Map();        // id -> {allow, deny, timer}
  const outbox = [];                // writes reported before the handshake arrived

  function send(msg) {
    if (port) { try { port.postMessage(Object.assign({ nonce }, msg)); } catch {} }
    else if (outbox.length < 50) outbox.push(msg);
  }

  // Handshake: the first matching message from this window wins; later ones (a page forging a
  // port) are swallowed and ignored.
  window.addEventListener("message", (e) => {
    const d = e.data;
    if (!d || typeof d !== "object" || d.__rampartBridge !== true) return;
    e.stopImmediatePropagation();
    if (port || e.source !== window || e.origin !== location.origin) return;
    if (typeof d.nonce !== "string" || !NONCE_RE.test(d.nonce) || !e.ports || e.ports.length !== 1) return;
    port = e.ports[0]; nonce = d.nonce;
    port.onmessage = (m) => {
      const r = m.data;
      if (!r || typeof r !== "object" || r.nonce !== nonce || r.type !== "clipboardDecision") return;
      const w = waiting.get(r.id); if (!w) return;
      if (r.pending === true) { clearTimeout(w.timer); return; }   // the user is being asked; wait for them
      clearTimeout(w.timer); waiting.delete(r.id);
      r.allow === true ? w.allow() : w.deny();
    };
    for (const m of outbox.splice(0)) send(m);
  }, true);

  function screen(text) {
    return new Promise((allow, deny) => {
      const id = ++seq;
      // Never hang the page forever if RamPart doesn't answer (no bridge, or the extension is reloading).
      const timer = setTimeout(() => { if (waiting.has(id)) { waiting.delete(id); allow(); } }, 8000);
      waiting.set(id, { allow, deny: () => deny(new DOMException("Blocked by RamPart", "NotAllowedError")), timer });
      send({ type: "clipboardWrite", id, text: String(text).slice(0, 5000) });
    });
  }

  // Patch the prototypes (not the instance) and lock them, so Clipboard.prototype.writeText.call(...)
  // and `delete navigator.clipboard.writeText` don't get around the hook. Honest limit: a fresh
  // same-origin iframe realm has its own unpatched prototypes (this script runs in the top frame only).
  function lock(obj, name, value) {
    try { Object.defineProperty(obj, name, { configurable: false, writable: false, enumerable: true, value }); } catch {}
  }
  const CP = typeof Clipboard !== "undefined" ? Clipboard.prototype : null;
  if (CP && CP.writeText) {
    const orig = CP.writeText;
    lock(CP, "writeText", function writeText(text) { const self = this; return screen(text).then(() => orig.call(self, text)); });
  }
  if (CP && CP.write) {
    const origW = CP.write;
    lock(CP, "write", async function write(items) {
      const self = this;
      let text = "";
      try { for (const it of items) if (it.types && it.types.includes("text/plain")) text += await (await it.getType("text/plain")).text(); } catch {}
      return screen(text).then(() => origW.call(self, items));
    });
  }
  const DP = Document.prototype;
  if (DP.execCommand) {
    const origExec = DP.execCommand;
    lock(DP, "execCommand", function execCommand(cmd, ...rest) {
      if (String(cmd).toLowerCase() === "copy") {
        const sel = String(getSelection() || "");
        const active = document.activeElement;
        const text = sel || (active && "value" in active ? String(active.value) : "");
        // execCommand is synchronous: report it; the content script's capture-phase copy handler decides.
        send({ type: "clipboardWrite", id: ++seq, text: text.slice(0, 5000), sync: true });
      }
      return origExec.call(this, cmd, ...rest);
    });
  }
})();
