#!/usr/bin/env python3
"""Build gated index.html for the WorldFirst Audience Map.

Reads the source HTML at Handoffs/audience_session/audience_map.html,
encrypts the body content with the `wf` password using AES-GCM,
and writes a self-contained gated index.html into this folder.

Re-run this whenever the source map updates. Then `git add . && git commit && git push`.
"""
import os
import base64
import json
import re
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

PASSWORD = "wf"
ITERATIONS = 100_000
LS_KEY = "audience_map_pw"
SOURCE = Path.home() / "Documents/Claude/Handoffs/audience_session/audience_map.html"
OUT = Path(__file__).parent / "index.html"


def encrypt_payload(plaintext: str, password: str = PASSWORD) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return {
        "v": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "iterations": ITERATIONS,
        "ciphertext": base64.b64encode(ct).decode("ascii"),
    }


def main():
    src = SOURCE.read_text()

    style_match = re.search(r"<style>([\s\S]*?)</style>", src)
    styles = style_match.group(1)

    body_match = re.search(r"<body>([\s\S]*?)</body>", src)
    body_content = body_match.group(1).strip()

    if "lock device" not in body_content:
        body_content = body_content.replace(
            "</footer>",
            f'<p style="margin-top: 14px; font-size: 11px;"><a href="#" onclick="localStorage.removeItem(\'{LS_KEY}\');location.reload();return false;" style="color: var(--ink-4); text-decoration: none;">lock device</a></p></footer>'
        )

    blob = encrypt_payload(body_content)
    payload_json = json.dumps(blob)

    out = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>WorldFirst Audience Map</title>
<style>
__STYLES__

/* Gate */
body.locked { overflow: hidden; }
body.locked #content > * { filter: blur(20px); pointer-events: none; user-select: none; }
#gate {
  position: fixed; inset: 0;
  display: flex; align-items: center; justify-content: center;
  background: rgba(245, 245, 247, 0.78);
  -webkit-backdrop-filter: saturate(180%) blur(10px);
  backdrop-filter: saturate(180%) blur(10px);
  z-index: 9999;
}
#gate-card {
  background: #fff;
  border: 1px solid #e5e5ea;
  border-radius: 12px;
  padding: 28px 30px;
  width: 320px;
  box-shadow: 0 6px 24px rgba(0,0,0,0.08);
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", "Segoe UI", system-ui, sans-serif;
}
#gate-card .lbl {
  font-size: 10.5px;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #86868b;
  font-weight: 600;
  margin-bottom: 6px;
}
#gate-card h2 {
  font-size: 18px;
  font-weight: 600;
  margin: 0 0 18px;
  letter-spacing: -0.01em;
  color: #1d1d1f;
}
#gate-form {
  display: flex; gap: 8px;
}
#gate-input {
  flex: 1;
  padding: 10px 12px;
  font-size: 14px;
  border: 1px solid #d2d2d7;
  border-radius: 6px;
  outline: none;
  background: #fff;
  color: #1d1d1f;
  font-family: inherit;
  -webkit-appearance: none;
}
#gate-input:focus {
  border-color: #0071e3;
  box-shadow: 0 0 0 3px rgba(0, 113, 227, 0.15);
}
#gate-btn {
  padding: 10px 16px;
  font-size: 13.5px;
  font-weight: 500;
  background: #1d1d1f;
  color: #fff;
  border: 0;
  border-radius: 6px;
  cursor: pointer;
  font-family: inherit;
}
#gate-btn:hover { background: #424245; }
#gate-err {
  font-size: 12px;
  color: #c0392b;
  margin-top: 10px;
  min-height: 16px;
}
</style>
</head>
<body class="locked">

<div id="gate">
  <div id="gate-card">
    <div class="lbl">Pipe · Audience</div>
    <h2>WorldFirst Audience Map</h2>
    <form id="gate-form" onsubmit="return gateSubmit(event)">
      <input id="gate-input" type="password" placeholder="password" autocomplete="off" autofocus>
      <button id="gate-btn" type="submit">Unlock</button>
    </form>
    <div id="gate-err"></div>
  </div>
</div>

<div id="content"></div>

<script type="application/json" id="payload">__PAYLOAD__</script>

<script>
const LS_KEY = "__LS_KEY__";

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveKey(password, salt, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false, ["decrypt"]
  );
}

async function decryptPayload(password) {
  const blob = JSON.parse(document.getElementById('payload').textContent);
  const salt = b64ToBytes(blob.salt);
  const iv = b64ToBytes(blob.iv);
  const ct = b64ToBytes(blob.ciphertext);
  const key = await deriveKey(password, salt, blob.iterations);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(plain);
}

function execInjectedScripts(container) {
  const scripts = container.querySelectorAll('script');
  scripts.forEach(oldScript => {
    const newScript = document.createElement('script');
    Array.from(oldScript.attributes).forEach(attr => newScript.setAttribute(attr.name, attr.value));
    newScript.textContent = oldScript.textContent;
    oldScript.parentNode.replaceChild(newScript, oldScript);
  });
}

function unlock(html) {
  const content = document.getElementById('content');
  content.innerHTML = html;
  execInjectedScripts(content);
  document.getElementById('gate').style.display = 'none';
  document.body.classList.remove('locked');
}

async function gateSubmit(e) {
  e.preventDefault();
  const inp = document.getElementById('gate-input');
  const err = document.getElementById('gate-err');
  err.textContent = '';
  try {
    const html = await decryptPayload(inp.value);
    unlock(html);
    try { localStorage.setItem(LS_KEY, inp.value); } catch (_) {}
  } catch (ex) {
    err.textContent = 'wrong password';
    inp.value = '';
    inp.focus();
  }
  return false;
}

(async () => {
  try {
    const cached = localStorage.getItem(LS_KEY);
    if (cached) {
      const html = await decryptPayload(cached);
      unlock(html);
    }
  } catch (_) {
    try { localStorage.removeItem(LS_KEY); } catch (_) {}
  }
})();
</script>
</body>
</html>
"""

    out = (out
           .replace("__STYLES__", styles)
           .replace("__PAYLOAD__", payload_json)
           .replace("__LS_KEY__", LS_KEY))

    OUT.write_text(out)
    print(f"wrote {OUT} ({len(out):,} bytes)")
    print(f"password: {PASSWORD}")


if __name__ == "__main__":
    main()
