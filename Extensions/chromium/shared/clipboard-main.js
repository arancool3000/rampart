// Runs in the page's MAIN world at document_start. Wraps the programmatic clipboard APIs so the
// isolated-world content script can screen what the page tries to put on the clipboard. The page
// sees a Promise that resolves once RamPart (or the user) allows the write.
(() => {
  if (window.__rampartClipboardHooked) return;
  window.__rampartClipboardHooked = true;
  let seq = 0;
  const waiting = new Map();
  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || e.data.__rampart !== "clipboardDecision") return;
    const w = waiting.get(e.data.id); if (!w) return;
    if (e.data.pending) return;            // the user is being asked; keep waiting
    waiting.delete(e.data.id);
    e.data.allow ? w.allow() : w.deny();
  });
  function screen(text) {
    return new Promise((allow, deny) => {
      const id = ++seq;
      waiting.set(id, { allow, deny: () => deny(new DOMException("Blocked by RamPart", "NotAllowedError")) });
      window.postMessage({ __rampart: "clipboardWrite", id, text: String(text).slice(0, 5000) }, "*");
      setTimeout(() => { if (waiting.has(id)) { waiting.delete(id); allow(); } }, 8000);   // never hang the page forever
    });
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
    Object.defineProperty(navigator.clipboard, "writeText", { configurable: true, writable: true, value: function (text) { return screen(text).then(() => orig(text)); } });
  }
  if (navigator.clipboard && navigator.clipboard.write) {
    const origW = navigator.clipboard.write.bind(navigator.clipboard);
    Object.defineProperty(navigator.clipboard, "write", { configurable: true, writable: true, value: async function (items) {
      let text = "";
      try { for (const it of items) if (it.types && it.types.includes("text/plain")) text += await (await it.getType("text/plain")).text(); } catch {}
      return screen(text).then(() => origW(items));
    } });
  }
  const origExec = document.execCommand && document.execCommand.bind(document);
  if (origExec) {
    document.execCommand = function (cmd, ...rest) {
      if (String(cmd).toLowerCase() === "copy") {
        const sel = String(getSelection() || "");
        const active = document.activeElement;
        const text = sel || (active && "value" in active ? String(active.value) : "");
        // execCommand is synchronous: report it, let the content script's capture-phase copy handler decide.
        window.postMessage({ __rampart: "clipboardWrite", id: ++seq, text: text.slice(0, 5000), sync: true }, "*");
      }
      return origExec(cmd, ...rest);
    };
  }
})();
