# react2shellburp (CVE-2025-55182)
Creator: **j0lt**

Burp Suite extension to detect the React Server Components unsafe deserialization vulnerability (React2Shell / CVE-2025-55182).

## Features
- Safe digest check (non-exploit) and PoC redirect check (high fidelity) with Unix/Windows payload toggle.
- Optional Burp Collaborator OOB confirmation in PoC mode.
- Custom headers, same-host redirect handling, and context-menu shortcuts.
- Passive fingerprinting for likely RSC endpoints; issues appear in Target/Scanner.

## Build
```bash
gradle clean shadowJar
```
Artifact: `build/libs/react2shellburp-0.1.0.jar`

## Install in Burp
Burp → Extender → Extensions → Add → Type: Java → Select `build/libs/react2shellburp-0.1.0.jar` → Open the **React2Shell** tab.

## Usage
1. Set target base URL/host and path (or right-click a request → “Load into React2Shell tab”).
2. Choose mode: Safe digest (low impact) or PoC redirect (strong confirmation; optional Collaborator).
3. Optional: add headers, enable redirects, toggle Windows payload.
4. Run scan. Findings appear in the activity log and as Burp issues (`React2Shell / CVE-2025-55182`).


## Safety
- Test only with authorization.
- Prefer Safe mode; use PoC/Collaborator when high-confidence evidence is required.
- Remediate by upgrading to patched React Server Components releases (19.0.1 / 19.1.2 / 19.2.1) or framework equivalents.
