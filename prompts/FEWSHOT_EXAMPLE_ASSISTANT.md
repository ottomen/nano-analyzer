`open_file`: `filePath` comes from renderer IPC. Passed directly to `fs.readFile()` with no path restriction — arbitrary file read. `open_external`: `url` comes from renderer input and is passed to `shell.openExternal()` without protocol validation. `get_config`: safe, validates sender and payload. `handle_message`: accesses `message.payload.filePath` without checking `message.type`.

```json
[
  {
    "severity": "high",
    "title": "Arbitrary file read via unchecked IPC path",
    "function": "ipcMain.handle('open-file')",
    "description": "Renderer-controlled filePath is passed directly to fs.readFile() without restricting it to an allowed directory"
  },
  {
    "severity": "high",
    "title": "Unsafe external URL handling",
    "function": "open_external()",
    "description": "Renderer-controlled url is passed to shell.openExternal() without validating protocol or destination"
  },
  {
    "severity": "high",
    "title": "Variant payload accessed without type validation",
    "function": "handle_message()",
    "description": "Accesses message.payload.filePath without checking message.type first"
  }
]
```
