# react2shellburp (CVE-2025-55182)
Creator: **j0lt**

Burp Suite extension for identifying the React Server Components unsafe deserialization vulnerability (React2Shell / CVE-2025-55182). It provides a focused UI tab, context-menu actions, active-scanner integration, and optional Burp Collaborator confirmation.

## Highlights
- Safe digest check (default) to detect vulnerable behavior without executing commands.
- PoC redirect check with customizable command (Unix/Windows) and same-host redirect handling.
- Optional Burp Collaborator mode (PoC only) that swaps in `curl`/`iwr` callbacks and waits for out-of-band confirmation.
- Custom headers, Windows toggle, and follow-redirect controls.
- Passive fingerprinting when responses resemble React Server Components (e.g., `text/x-component`, `resolved_model`, `$@`, RSC headers).
- Context menu to load a request into the tab or run a quick scan; active scans reuse current tab settings.

## Build
```bash
gradle shadowJar
```
Artifact: `build/libs/react2shellburp-0.1.0.jar`

## Load into Burp
1) Burp → Extender → Extensions → Add  
2) Type: Java; select `build/libs/react2shellburp-0.1.0.jar`  
3) Open the **React2Shell** tab

## Using the tab
1) Set target base URL/host and path (or right-click a request → “Load into React2Shell tab”).  
2) Choose mode:
   - **Safe digest check**: looks for `500` with `E{"digest"}` while excluding common host-based mitigations.
   - **PoC redirect check**: triggers `X-Action-Redirect` `/login?a=<output>` for high-confidence confirmation; command is editable per OS toggle.
3) Optional: add headers, enable same-host redirect following, toggle Windows payload.
4) Optional (PoC): enable Burp Collaborator to swap the command with a `curl`/`iwr` callback and wait for interactions.
5) Run scan; results appear in the activity log and as Burp Scanner issues.

## Detection logic
- Sends `POST` with `Next-Action`/`X-Nextjs-*` headers and a crafted multipart payload targeting Server Actions.
- Safe mode: vulnerable if `500` + `E{"digest"}` is returned without known mitigation signatures.
- PoC mode: vulnerable if `X-Action-Redirect` contains `/login?a=...`; collaborator mode marks vulnerable on observed callbacks.

## Active Scanner & Findings
- Passive scan: flags likely RSC endpoints (issues appear in Scanner/Target > Issue Activity).
- Active scan: reuses current tab options; if vulnerable, issues are added with request/response evidence and collaborator hits when enabled.
- Target/Issue tabs will show `React2Shell / CVE-2025-55182` entries with severity High when exploitation indicators are found; informational issues appear for RSC fingerprints.

## Releases (GitHub)
1) Build the fat jar: `gradle clean shadowJar` (output: `build/libs/react2shellburp-0.1.0.jar`).
2) Tag the commit, e.g. `git tag v0.1.0 && git push --tags`.
3) Create a GitHub Release for the tag and upload `build/libs/react2shellburp-0.1.0.jar` as an asset. Repeat per version.

## Notes & Safety
- Use only on targets you are authorized to test.
- Default to safe mode for low impact; use PoC or Collaborator mode when stronger confirmation is needed.
- Remediate by upgrading to patched React Server Components releases (19.0.1 / 19.1.2 / 19.2.1) or framework versions that include the fix; disabling Server Actions is a temporary mitigation.
