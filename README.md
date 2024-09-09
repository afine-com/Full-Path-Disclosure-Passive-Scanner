# FPD Scanner

FPD Scanner is a Burp Suite extension that passively scans HTTP responses for full path disclosure (FPD) vulnerabilities. It highlights paths that could expose sensitive information about a server's file structure, such as file paths in Windows and Unix/Linux environments.

## Features:
- Identifies full path disclosure vulnerabilities in HTTP responses.
- Detects Windows-style and Unix/Linux-style file paths.
- Excludes false positives caused by JavaScript Unicode encoding sequences.
- Supports passive scanning to ensure no active interference with the target server.

## Installation

To use the FPD Scanner, follow these steps:

1. Open Burp Suite.
2. Go to the `Extender` tab.
3. Click `Add` and select `Python` as the extension type.
4. Select the `FPDScanner.py` file and click `Next` to load the extension.

The extension will now run in the background, scanning all HTTP responses for full path disclosure vulnerabilities.

## How to use

Once the extension is loaded:

1. Perform regular HTTP/HTTPS traffic interception using Burp Suite.
2. The extension will passively scan all HTTP responses for file paths that might expose sensitive information (e.g., `C:\Users\TestUser\Documents\secret.txt` or `/etc/passwd`).
3. Detected vulnerabilities will be reported in the Issues tab.
4. You can also force a passive scan by right-clicking on the selected target in the sitemap tree and clicking Passively scan this host.

## Dependencies
- Jython 2.7.2 or higher is required to run this Python extension.
