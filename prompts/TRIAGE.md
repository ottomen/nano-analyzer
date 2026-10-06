A vulnerability scanner flagged this in {project_name}. Is it real?

Be skeptical — most scanner findings are false positives.

RULES:

- VALID: the bug is real AND an external attacker, malicious renderer, malicious file, network input, or other untrusted source can trigger it to cause meaningful harm such as code execution, arbitrary file access, privilege escalation, data corruption, auth bypass, or sensitive data exposure. The attacker must control the input that reaches the vulnerable operation.
- INVALID: the bug pattern does not exist, OR it is not attacker-reachable, OR only trusted internal callers can reach it, OR a concrete defense prevents exploitation, OR it is only a code-quality/reliability issue.
- UNCERTAIN: only if you genuinely cannot determine.

Electron trust boundaries matter. Trace inputs across:

`renderer → preload → IPC → main process → Electron / Node.js / OS API`

Also consider input from network responses, files, URLs, custom protocols, command-line arguments, persisted state, USB/serial/Bluetooth devices, and embedded web content.

ABSENCE OF DEFENSE: If the bug pattern clearly exists, attacker-controlled input reaches it, and you searched for a defense but did not find one, lean toward VALID rather than UNCERTAIN.

Do not assume a renderer is trusted merely because it belongs to the application.

CRITICAL: When citing a defense, verify that it actually blocks the reported attack.

Examples:

- IPC sender validation: verify the actual `event.sender`, `event.senderFrame`, URL, origin, or `WebContents` check.
- Path restriction: resolve how the path is constructed and verify that traversal or absolute paths cannot escape the allowed directory.
- URL validation: verify the actual allowed protocols, origins, and hostnames.
- Payload validation: verify runtime validation, not just TypeScript types.
- Permission checks: verify the exact window/frame/origin conditions.
- Numeric limits: resolve constants and verify that the effective value is sufficient.
- BrowserWindow security: verify actual values of `contextIsolation`, `sandbox`, `nodeIntegration`, `webSecurity`, and related settings.

"There is validation" is NOT enough. Show why the validation blocks this specific path.

FOLLOW DATA FLOW: When a value is passed between functions, IPC handlers, preload APIs, or modules, grep for the relevant names and trace it to its source and sink.

If a function receives attacker-controlled input, grep for its callers.

If an IPC handler is involved, grep for:

- the IPC channel name
- its renderer/preload caller
- the main-process handler

If a `contextBridge` API is involved, grep for the exposed API name.

If configuration affects exploitability, grep for the actual BrowserWindow/session/permission configuration.

IMPORTANT: If your own analysis establishes the conclusion, do not contradict it later in the response.

If you believe a defense exists, you must name and verify the specific function, condition, configuration, or validation that implements it. Do not rely on vague assumptions such as "the renderer is trusted", "another layer probably validates this", or "TypeScript ensures the type".

GREP TOOL: Include a grep pattern in the JSON to search the codebase.

Use function names, IPC channel names, variables, configuration keys, or API names, for example:

`"open-file"`
`"ipcMain.handle"`
`"exposeInMainWorld"`
`"setPermissionCheckHandler"`
`"contextIsolation"`
`"filePath"`
`"openExternal"`

Do NOT prefix patterns with file paths.

Use your knowledge of {project_name} and Electron for intuition, but verify project-specific claims via grep. Do not invent defenses.

Respond ONLY with JSON:

{{"reasoning": "Analyze the attacker-controlled source, trust boundary, vulnerable sink, and any verified defenses. State the conclusion clearly.",
"crux": "the single key fact the verdict depends on",
"grep": "search_pattern to verify the crux",
"verdict": "VALID/INVALID/UNCERTAIN"}}

---

**Reported vulnerability:**
{finding}

**Code from {filepath}:**

```ts
{code}
```
