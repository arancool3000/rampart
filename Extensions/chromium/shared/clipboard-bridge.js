// Isolated world, document_start (before any page script). Creates the private MessageChannel the
// MAIN-world clipboard hook (shared/clipboard-main.js) reports through, so page scripts can neither
// forge a "clipboardDecision" nor a "clipboardWrite" (N4, harden-hx6). content.js (document_idle)
// registers its handler with RampartClipboardBridge.onWrite; writes that arrive earlier are queued.
// content.js carries a copy of installRampartClipboardBridge for browsers whose manifest doesn't
// list this file yet (Safari: needs owner); that late fallback is weaker (a page can race it).
function installRampartClipboardBridge() {
  if (globalThis.RampartClipboardBridge) return globalThis.RampartClipboardBridge;
  const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
  const nonce = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const ch = new MessageChannel();
  const queue = [];
  let handler = null;
  ch.port1.onmessage = (m) => {
    const d = m.data;
    if (!d || typeof d !== "object" || d.nonce !== nonce || d.type !== "clipboardWrite") return;
    if (typeof d.id !== "number" || !Number.isSafeInteger(d.id) || typeof d.text !== "string") return;
    const msg = { id: d.id, text: d.text.slice(0, 5000), sync: d.sync === true };
    if (handler) handler(msg); else if (queue.length < 50) queue.push(msg);
  };
  window.postMessage({ __rampartBridge: true, nonce }, "*", [ch.port2]);   // target is this same window
  const bridge = Object.freeze({
    onWrite(fn) { handler = fn; for (const m of queue.splice(0)) fn(m); },
    decide(id, allow, pending) { try { ch.port1.postMessage({ type: "clipboardDecision", nonce, id, allow: allow === true, pending: pending === true }); } catch {} },
  });
  globalThis.RampartClipboardBridge = bridge;
  return bridge;
}
if (window.top === window) installRampartClipboardBridge();
