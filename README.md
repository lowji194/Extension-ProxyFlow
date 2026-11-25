<div align="center">
  <img src="icons/logo.svg" width="84" height="84" alt="ProxyFlow logo">
  <h1>ProxyFlow</h1>
  <p><strong>Fast, privacy-first Chromium proxy switcher with Auto Switch rules, PAC routing, encrypted local vault, and network diagnostics.</strong></p>
  <p>
    Manifest V3 &bull; Browser-Level Routing &bull; Light-Mode UI &bull; AES-256-GCM Local Vault
  </p>
</div>

---

## Overview

**ProxyFlow** is a Chromium extension (Google Chrome, Microsoft Edge, Brave) designed strictly for browser-level proxy management without interfering with OS/Windows-wide VPN or system proxy settings. Switch effortlessly between **Direct (Off)**, a selected **Proxy Server**, or **Auto Switch** routing rules per website.

## Key Features

- **3-State Visual Toolbar Indicator**:
  - 🔴 **Red ring** — `Direct (Off)`: browser traffic connects directly without a proxy.
  - 🟢 **Green ring** — `Proxy Active`: browser traffic routes through the selected proxy profile.
  - 🟣 **Purple ring** — `Auto Switch`: rule-based routing per site/URL (displays a **green center dot** when the active tab routes through a proxy).
- **Smart Auto Switch & PAC Compiler**:
  - Supports `hostWildcard`, `hostRegex`, `urlWildcard`, `urlRegex`, `cidr`, and `keyword` condition matching.
  - Preconfigured with 6 standard local/LAN bypass rules (`<local>`, `localhost`, `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`).
  - Supports **Temp Rules** per domain directly from the popup, attached AutoProxy / Switchy **Rule Lists**, and custom PAC profiles.
- **Multi-Protocol & Flexible Import**:
  - Supports `HTTP`, `HTTPS`, `SOCKS4`, and `SOCKS5` proxies (authenticated HTTP/HTTPS handled automatically via `webRequestAuthProvider`).
  - Quick add and bulk import parser accepting `ip:port:user:pass`, `user:pass@ip:port`, and URI formats (`http://`, `https://`, `socks4://`, `socks5://`).
- **Standard HTTPS IP & Live Probes**:
  - Verifies active proxy status, public IP, and latency against standard HTTPS trace/IP endpoints: Cloudflare Trace (`cloudflare.com/cdn-cgi/trace`, `1.1.1.1/cdn-cgi/trace`), `icanhazip.com`, and `ipify.org`.
  - Built-in **Network Monitor** (`monitor.html`) captures failed requests and lets you create bypass/proxy rules in one click.
- **Privacy-First Encrypted Storage**:
  - Extension profiles and credentials are encrypted locally inside `chrome.storage.local` (`pmStateVault`) using **AES-256-GCM** (`Web Crypto API`).
  - Export/restore **passphrase-protected backups** encrypted with **PBKDF2-SHA256** (150,000 iterations) + **AES-256-GCM**, or export a standalone `proxyflow.pac` file.
  - Zero telemetry, zero external analytics, and zero third-party CDNs.

## Installation (Developer Mode)

1. Clone or download this repository:
   ```bash
   git clone https://github.com/lowji194/Extension-ProxyFlow.git
   ```
2. Open `chrome://extensions` (or `edge://extensions`) in your Chromium browser.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the cloned `Extension-ProxyFlow` folder.

## Keyboard Shortcuts

| Shortcut | Action |
| --- | --- |
| `Alt+Shift+O` | Open the ProxyFlow popup |
| `Alt+Shift+P` | Cycle through Quick Switch profiles |

*(You can customize shortcuts anytime at `chrome://extensions/shortcuts`.)*

## Project Structure

```text
├── manifest.json             # MV3 manifest, permissions, shortcuts, and icon declarations
├── background.js             # Service worker: proxy state controller, PAC applicator, auth & probes
├── popup.html / popup.js     # Compact Light-Mode popup UI (mode switching, IP check, quick add/edit)
├── options.html / options.js # Full Options Console (proxies, Auto Switch studio, backup/export, settings)
├── monitor.html / monitor.js # Live Network Request Monitor for failed domains and quick rules
├── icons/                    # Brand vector SVG and Chrome Web Store PNG icons (16, 32, 48, 128)
├── shared/                   # ES modules: models, AES-256-GCM storage, rule/PAC compiler, IP probes, UI helpers
└── styles/                   # Light-Mode semantic tokens and component stylesheets
```

## Permissions Explained

| Permission | Purpose |
| --- | --- |
| `proxy` | Apply browser proxy configuration (`direct`, `fixed_servers`, or `pac_script`) |
| `storage` / `unlimitedStorage` | Persist encrypted proxy profiles, rules, and settings locally |
| `webRequest` / `webRequestAuthProvider` | Supply HTTP/HTTPS proxy credentials and observe failed network requests for Monitor |
| `tabs` | Match the active tab URL to update toolbar status and trigger optional refresh on switch |
| `alarms` | Run optional periodic batch checks and PAC/rule list refreshes reliably in MV3 |
| `contextMenus` | Provide quick route inspection entries from page/link context menus |
| `<all_urls>` | Required by Chromium proxy auth challenges and active-tab request monitoring |

---

## ☕ Buy me a coffee

If you find this project useful, consider buying me a coffee to support its maintenance and development. Thank you!

<p align="center">
  <a href="https://raw.githubusercontent.com/lowji194/lowji194/main/assets/donate-qr.svg"><img src="https://raw.githubusercontent.com/lowji194/lowji194/main/assets/donate-qr.svg" width="300" alt="Donate — scan the QR code"></a>
</p>
