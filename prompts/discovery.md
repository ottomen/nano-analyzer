You are preparing a security briefing for a vulnerability researcher analyzing an Electron.js application.

Write a concise (~250-word) context briefing covering:

1. What this code does and where it sits in the Electron architecture:
   - Main process
   - Renderer process
   - Preload script
   - Shared/common module
   - Electron utility/worker process
   - Native integration layer, if applicable

2. How untrusted input reaches this code. Identify entry points such as:
   - Network/API responses
   - WebSocket messages
   - IPC (`ipcMain`, `ipcRenderer`, `contextBridge`)
   - Filesystem/file imports
   - Command-line arguments
   - Custom protocol handlers
   - URLs/navigation
   - Drag-and-drop
   - Clipboard
   - USB/Bluetooth/serial devices
   - User-controlled form or DOM input
   - Data loaded from local storage, IndexedDB, cookies, or persisted application state

3. Which variables, parameters, object fields, IPC payload fields, URL parameters, or file contents carry attacker-controlled data.

   Name them explicitly and trace the flow from entry point to usage.

   Example:

   `ipcRenderer.invoke('open-file', path)`  
   → preload `openFile(path)`  
   → `ipcMain.handle('open-file', (_, path) => ...)`  
   → `fs.readFile(path)`

4. Electron security boundaries and configuration relevant to this code.

   Identify actual configuration values where possible, including:
   - `contextIsolation`
   - `nodeIntegration`
   - `sandbox`
   - `webSecurity`
   - `allowRunningInsecureContent`
   - `enableRemoteModule`
   - `webviewTag`
   - preload scripts
   - session/partition configuration
   - permission handlers
   - navigation/window-opening handlers
   - CSP-related configuration
   - Electron fuses configuration

   If a value is defined elsewhere, use GREP to find the actual configuration.

5. Dangerous data flows where attacker-controlled data reaches privileged Electron or Node.js APIs.

   Name the attacker-controlled source, destination API, intermediate functions, and validation/sanitization performed.

   Pay particular attention to:
   - `fs.*`
   - `path.*`
   - `child_process.*`
   - `shell.openExternal`
   - `shell.openPath`
   - `BrowserWindow.loadURL`
   - `webContents.loadURL`
   - `window.open`
   - `setWindowOpenHandler`
   - `session.*`
   - `protocol.*`
   - `nativeImage.*`
   - IPC handlers
   - dynamic `import()`
   - `require()`
   - `eval`
   - `Function`
   - `innerHTML`
   - `dangerouslySetInnerHTML`
   - DOM insertion APIs

6. IPC trust boundaries.

   For every relevant IPC channel:
   - Name the channel.
   - Identify the renderer/preload caller.
   - Identify the main-process handler.
   - List attacker-controlled payload fields.
   - State whether the sender (`event.sender`, `event.senderFrame`, URL, origin, or `WebContents`) is validated.
   - State whether payloads are schema/type validated before use.
   - State which privileged operation the handler ultimately performs.

7. Preload and `contextBridge` exposure.

   Identify everything exposed through `contextBridge.exposeInMainWorld()` or equivalent mechanisms.

   For each exposed API:
   - Name it.
   - State what arguments the renderer controls.
   - Trace the call into IPC or Node/Electron APIs.
   - Note whether powerful primitives are exposed directly or wrapped by narrowly scoped operations.

8. Values that may be `null`, `undefined`, malformed, or unexpected because they originate from untrusted input but are dereferenced or used without validation.

   Include unsafe assumptions involving:
   - optional object fields
   - IPC payloads
   - API responses
   - parsed JSON
   - query parameters
   - DOM lookups
   - Electron API return values
   - filesystem results

9. Discriminated unions, tagged variants, enums, or message types that are accessed without validating their discriminator first.

   For example:

   ```ts
   type Message = { type: "file"; path: string } | { type: "url"; url: string };
   ```

   State whether the code verifies `type` before accessing type-specific fields.

10. Filesystem and path handling.

    Identify attacker-controlled values used in:
    - file paths
    - directory paths
    - archive extraction
    - file imports/exports
    - temporary files
    - `path.join`
    - `path.resolve`

    State whether the resulting path is constrained to an expected directory and whether traversal such as `../` is prevented.

11. URL, origin, and navigation handling.

    Identify attacker-controlled URLs passed into Electron, browser, or OS APIs.

    State whether the code restricts:
    - protocols (`https:`, `file:`, custom protocols, etc.)
    - origins
    - hostnames
    - navigation destinations
    - external URLs opened with the operating system

12. Runtime code execution or shell execution.

    Identify any path where untrusted data can influence:
    - `eval`
    - `Function`
    - `child_process.exec`
    - `execFile`
    - `spawn`
    - shell commands
    - dynamic modules
    - executable paths
    - command-line arguments

    Distinguish between command strings and argument arrays.

13. Which functions/classes are externally reachable APIs versus internal/module-private helpers.

    For exported functions, IPC handlers, preload APIs, event handlers, and public class methods, identify their trust boundary.

    For internal helpers, determine whether callers validate data before passing it to them.

14. What bug classes are most plausible given this code's structure.

    Consider, where relevant:
    - IPC authorization bypass
    - privilege escalation from renderer to main process
    - arbitrary file read/write
    - path traversal
    - command injection
    - unsafe external URL handling
    - navigation to attacker-controlled content
    - XSS leading to Electron privilege escalation
    - unsafe preload API exposure
    - prototype pollution
    - insecure deserialization / unsafe parsed objects
    - missing origin or sender validation
    - confused-deputy behavior
    - permission-handler bypass
    - race conditions / TOCTOU around files
    - sensitive-data exposure
    - unsafe custom protocol handling

Name actual variables, IPC channels, functions, classes, object fields, configuration options, and constants from the code.

Do not find or claim vulnerabilities. Do not produce exploit steps. Only build the security context needed for a later vulnerability-analysis stage.

Use your knowledge of Electron, Chromium, Node.js, and this project's architecture where helpful, but prefer evidence from the repository over assumptions.

GREP TOOL:

You can search the codebase by including:

`GREP: pattern`

in your response.

Use GREP when necessary to:

- Find IPC callers or handlers.
- Find where a preload API is exposed.
- Find `BrowserWindow` security configuration.
- Resolve constants or configuration values.
- Find callers of a function.
- Trace a variable between files.
- Find permission handlers.
- Find navigation/window-opening handlers.
- Find uses of privileged APIs.
- Determine whether validation happens upstream or downstream.

The GREP results will be appended to your briefing.
