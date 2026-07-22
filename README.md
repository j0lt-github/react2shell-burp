# React2Shell RCE Scanner and Validator (CVE-2025-55182)
Creator: **j0lt**  
Collaborator: https://github.com/shashank18  

A Burp Suite extension that detects and validates the React2Shell vulnerability (CVE-2025-55182) — a pre-authentication remote code execution flaw in React Server Components. The extension passively fingerprints RSC endpoints and actively probes for unsafe deserialization via two scan modes.

## Features
- **Safe digest check** (non-exploit): confirms the vulnerable deserialization path by triggering a 500 + digest error — no code execution.
- **PoC redirect check** (high fidelity): executes a command and captures output via the `X-Action-Redirect` header, providing strong exploitation confirmation.
- **Burp Collaborator OOB** confirmation in PoC mode with non-blocking 60-second scheduled polling.
- Unix and Windows payload toggles; custom headers; same-host redirect following.
- Passive fingerprinting for RSC endpoints — findings appear in Target and Scanner panels.
- Context-menu shortcuts in Proxy history, Target site map, and Scanner results.

## Build
```bash
./gradlew clean shadowJar
```
Artifact: `build/libs/react2shellburp-0.1.1.jar`

## Install in Burp
Burp → Extender → Extensions → Add → Type: Java → Select `build/libs/react2shellburp-0.1.1.jar` → Open the **React2Shell** tab.

## Usage
1. Set target base URL/host and path (or right-click a request → **Load into React2Shell tab**).
2. Choose mode: **Safe digest** (low impact) or **PoC redirect** (strong confirmation; optional Collaborator OOB).
3. Optional: add custom headers, enable redirect following, toggle Windows payload.
4. Click **Run scan**. Findings appear in the activity log and as Burp issues (`React2Shell / CVE-2025-55182`).

## Safety
- Test only on systems you are authorized to assess.
- Prefer Safe mode; use PoC/Collaborator only when high-confidence evidence is required.
- Remediate by upgrading to patched React Server Components releases (19.0.1 / 19.1.2 / 19.2.1) or framework equivalents.
