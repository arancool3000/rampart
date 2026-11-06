import Foundation
import WebKit
import RampartWeb

/// Two user scripts:
///  1. `pageWorldShim` runs in the page's own world because that is the only place where
///     `navigator.clipboard.writeText` and `DataTransfer.setData` can be intercepted. It never
///     talks to native directly (the page could spoof that); it writes an attribute on <html> and
///     fires a DOM event that the isolated-world scanner picks up.
///  2. `scanner` runs in an isolated WKContentWorld (`rampart`), scans the DOM for ClickFix text,
///     scareware overlays, drainer prompts, credential forms, hidden frames, and posts findings
///     through WKScriptMessageHandler. Page scripts cannot see or alter it.
enum ContentScript {
    static let world = WKContentWorld.world(name: "rampart")
    static let findingsHandler = "rampartFindings"
    static let formsHandler = "rampartForms"
    static let clipboardHandler = "rampartClipboard"

    static let clipboardMarkers: [String] = ClipboardRule.shellMarkers
    static let clickFixVerify = ClickFixRule.verifyPhrases
    static let clickFixActions = ClickFixRule.actionPhrases
    static let scarePhrases = ScarewareRule.phrases
    static let drainerPhrases = ["connect wallet", "connect your wallet", "seed phrase", "recovery phrase", "secret phrase", "12-word", "24-word", "claim airdrop",
                                 "claim your airdrop", "claim rewards", "mint now", "wallet verification", "validate wallet", "sync wallet", "restore wallet",
                                 "import wallet", "private key", "approve all", "setapprovalforall", "eth_sign", "permit2", "unlimited approval"]
    static var brandKeywords: [String] { BrandList.brands.flatMap(\.keywords).filter { $0.count >= 4 } }

    static func jsArray(_ a: [String]) -> String {
        let data = try! JSONSerialization.data(withJSONObject: a, options: [])
        return String(decoding: data, as: UTF8.self)
    }

    static var pageWorldShim: String {
        """
        (function(){
          if (window.__rampartShim) return; window.__rampartShim = true;
          const MARKERS = \(jsArray(clipboardMarkers));
          const REPLACEMENT = "RamPart blocked a command this page tried to copy to your clipboard.";
          function suspicious(t){
            if (typeof t !== 'string') return false; const s = t.toLowerCase().trim();
            if (s.length < 6 || s.length > 4000) return false;
            for (const m of MARKERS) if (s.includes(m)) return true;
            if (/^(\\/bin\\/|\\/usr\\/bin\\/|~\\/)?[a-z0-9_.-]{2,20}\\s+.*https?:\\/\\//.test(s)) return true;
            if (s.startsWith('echo ') && s.includes('|')) return true;
            return false;
          }
          function report(t){
            try {
              const html = document.documentElement;
              html.setAttribute('data-rampart-clipboard', String(t).slice(0, 400));
              html.dispatchEvent(new Event('rampart-clipboard-blocked'));
            } catch(e){}
          }
          try {
            const cb = navigator.clipboard;
            if (cb) {
              const origText = cb.writeText.bind(cb);
              const origWrite = cb.write ? cb.write.bind(cb) : null;
              Object.defineProperty(cb, 'writeText', { configurable:false, writable:false, value: function(t){
                if (suspicious(t)) { report(t); return origText(REPLACEMENT); }
                return origText(t);
              }});
              if (origWrite) Object.defineProperty(cb, 'write', { configurable:false, writable:false, value: function(items){
                try { for (const it of items) { if (it.types && it.types.includes('text/plain')) { report('[clipboard.write with text/plain]'); return origText(REPLACEMENT); } } } catch(e){}
                return origWrite(items);
              }});
            }
            const origSet = DataTransfer.prototype.setData;
            DataTransfer.prototype.setData = function(type, data){
              if (/text/.test(String(type)) && suspicious(data)) { report(data); return origSet.call(this, type, REPLACEMENT); }
              return origSet.call(this, type, data);
            };
            const origExec = document.execCommand.bind(document);
            document.execCommand = function(cmd, ui, val){
              if (String(cmd).toLowerCase() === 'copy') {
                const sel = String(window.getSelection && window.getSelection());
                const active = document.activeElement; const v = active && 'value' in active ? String(active.value) : '';
                if (suspicious(sel) || suspicious(v)) {
                  report(suspicious(sel) ? sel : v);
                  try { if (active && 'value' in active) { active.value = REPLACEMENT; active.select && active.select(); } } catch(e){}
                }
              }
              return origExec(cmd, ui, val);
            };
          } catch(e){}
        })();
        """
    }

    static var scanner: String {
        """
        (function(){
          if (window.__rampartScan) return; window.__rampartScan = true;
          const VERIFY = \(jsArray(clickFixVerify)), ACTIONS = \(jsArray(clickFixActions)), SCARE = \(jsArray(scarePhrases));
          const DRAIN = \(jsArray(drainerPhrases)), BRANDS = \(jsArray(brandKeywords));
          const post = (name, body) => { try { window.webkit.messageHandlers[name].postMessage(body); } catch(e){} };
          const sent = new Set();
          function excerpt(text, phrase){ const i = text.toLowerCase().indexOf(phrase); if (i < 0) return text.slice(0,200); return text.slice(Math.max(0,i-80), i+160).replace(/\\s+/g,' '); }
          function count(text, list){ const t = text.toLowerCase(); return list.filter(p => t.includes(p)); }
          function overlays(){
            const out = []; const W = innerWidth, H = innerHeight;
            for (const el of document.querySelectorAll('body *')) {
              const cs = getComputedStyle(el); if (cs.position !== 'fixed' && cs.position !== 'absolute') continue;
              const r = el.getBoundingClientRect(); if (r.width < W*0.9 || r.height < H*0.9) continue;
              out.push({el, text: (el.innerText||'').trim(), opacity: parseFloat(cs.opacity||'1'), pe: cs.pointerEvents, z: cs.zIndex});
            }
            return out;
          }
          function scan(){
            const findings = []; const text = (document.body ? document.body.innerText : '').slice(0, 60000);
            const ovs = overlays(); const ovText = ovs.map(o => o.text).join('\\n');
            for (const src of [text, ovText]) {
              if (count(src, VERIFY).length >= 1 && count(src, ACTIONS).length >= 2) { findings.push({kind:'fakeCaptcha', detail: count(src, ACTIONS).slice(0,3).join(', '), sample: excerpt(src, count(src, ACTIONS)[0])}); break; }
            }
            const sc = count(text + '\\n' + ovText, SCARE); if (sc.length >= 2) findings.push({kind:'fakeVirusAlert', detail: sc.slice(0,3).join(', '), sample: excerpt(text + ovText, sc[0])});
            const inline = Array.from(document.scripts).filter(s => !s.src).map(s => s.textContent.slice(0, 20000)).join('\\n').toLowerCase();
            const dr = count(text, DRAIN); const drs = count(inline, ['setapprovalforall','eth_sign','permit2','drainer','0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff']);
            if (dr.length >= 2 || (dr.length >= 1 && drs.length >= 1) || (window.ethereum === undefined && drs.length >= 2)) findings.push({kind:'walletDrainer', detail: (dr.concat(drs)).slice(0,3).join(', '), sample: dr.length ? excerpt(text, dr[0]) : null});
            for (const f of document.querySelectorAll('iframe')) {
              const r = f.getBoundingClientRect(); let host = ''; try { host = new URL(f.src, location.href).host; } catch(e){}
              if (host && host !== location.host && (r.width <= 2 || r.height <= 2 || r.right < 0 || r.bottom < 0)) findings.push({kind:'hiddenIframe', detail: host, sample: null});
            }
            for (const o of ovs) if (o.opacity <= 0.05 && o.pe !== 'none' && o.text.length === 0) { findings.push({kind:'overlayCapture', detail: 'z-index ' + o.z, sample: null}); break; }
            const fresh = findings.filter(f => !sent.has(f.kind + ':' + f.detail)); fresh.forEach(f => sent.add(f.kind + ':' + f.detail));
            if (fresh.length) post('\(findingsHandler)', {findings: fresh});
            // Credential forms: native decides whether the host is a look-alike for the brands shown.
            const forms = [];
            for (const form of document.querySelectorAll('form')) {
              const pw = form.querySelector('input[type=password]'); if (!pw) continue;
              let action = ''; try { action = new URL(form.getAttribute('action') || location.href, location.href).href; } catch(e){}
              forms.push({action, hasEmailOrUser: !!form.querySelector('input[type=email],input[type=text],input[name*=user],input[name*=login]'), hasCard: !!form.querySelector('input[autocomplete*=cc-],input[name*=card]'), hasOTP: !!form.querySelector('input[autocomplete=one-time-code],input[name*=otp]')});
            }
            if (forms.length && !sent.has('forms')) {
              sent.add('forms');
              const hay = (document.title + ' ' + text.slice(0, 4000) + ' ' + Array.from(document.images).map(i => (i.alt||'') + ' ' + (i.src||'').split('/').pop()).join(' ')).toLowerCase();
              const hints = BRANDS.filter(b => hay.includes(b)).slice(0, 8);
              post('\(formsHandler)', {forms, brandHints: hints, title: document.title});
            }
          }
          document.documentElement.addEventListener('rampart-clipboard-blocked', () => {
            const t = document.documentElement.getAttribute('data-rampart-clipboard') || '';
            post('\(clipboardHandler)', {findings: [{kind:'clipboardCommand', detail: t.slice(0, 80), sample: t}]});
          });
          let timer = null; const schedule = () => { clearTimeout(timer); timer = setTimeout(scan, 600); };
          if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', schedule); else schedule();
          window.addEventListener('load', () => setTimeout(scan, 1200));
          try { new MutationObserver(schedule).observe(document.documentElement, {childList:true, subtree:true, characterData:true}); } catch(e){}
        })();
        """
    }

    static func install(into controller: WKUserContentController, handler: WKScriptMessageHandler) {
        controller.addUserScript(WKUserScript(source: pageWorldShim, injectionTime: .atDocumentStart, forMainFrameOnly: false, in: .page))
        controller.addUserScript(WKUserScript(source: scanner, injectionTime: .atDocumentEnd, forMainFrameOnly: false, in: world))
        for name in [findingsHandler, formsHandler, clipboardHandler] {
            controller.add(handler, contentWorld: world, name: name)
        }
    }
}
