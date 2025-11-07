# Speakeasy Module - Future Improvements

This document outlines planned enhancements to dionaea's Speakeasy integration that have been identified but not yet implemented.

## 5. Extract Additional IOCs

**Status**: Planned
**Priority**: Medium
**Complexity**: Low-Medium

### Description
The Speakeasy emulation report contains valuable indicators of compromise that we're not currently extracting:

- **dropped_files** - Files written to disk by the shellcode
- **dynamic_code_segments** - Code that was dynamically allocated and executed (unpacking)
- **process_events** - Process injection attempts and child process creation
- **file_access** - File system operations
- **registry_access** - Registry operations

### Implementation Notes

Add new detection methods to extract these events:

```python
def _process_entry_point(self, ep: dict, con: connection | None) -> None:
    """Process a single entry point from the emulation report."""

    # Extract dropped files
    dropped_files = ep.get('dropped_files', [])
    for f in dropped_files:
        path = f.get('path')
        data = f.get('data')  # Base64 encoded
        logger.info("Dropped file: %s", path)
        # Could save to dionaea's binaries directory

    # Extract dynamic code segments (unpacking detection)
    dynamic_segments = ep.get('dynamic_code_segments', [])
    if dynamic_segments:
        logger.info("Detected %d dynamic code segments (possible unpacking)",
                   len(dynamic_segments))
        # Could trigger additional analysis on unpacked code

    # Extract process events (injection, child processes)
    process_events = ep.get('process_events', [])
    for event in process_events:
        event_type = event.get('event')  # 'create', 'inject', etc.
        pid = event.get('pid')
        path = event.get('path')
        cmdline = event.get('cmdline')

        if event_type == 'create':
            logger.info("Process creation: %s %s", path, cmdline)
        elif event_type == 'inject':
            logger.info("Process injection into PID %d", pid)

    # Extract file access
    file_access = ep.get('file_access', [])
    for access in file_access:
        operation = access.get('operation')  # 'read', 'write', 'delete'
        path = access.get('path')
        logger.info("File %s: %s", operation, path)

    # Extract registry access
    registry_access = ep.get('registry_access', [])
    for access in registry_access:
        operation = access.get('operation')  # 'read', 'write', 'delete'
        key = access.get('key')
        value = access.get('value')
        logger.info("Registry %s: %s\\%s", operation, key, value)
```

### Benefits
- Detect file-dropping malware
- Identify unpacking/decryption behavior
- Track process injection attempts
- Monitor file system and registry manipulation

---

## 6. Custom Configuration Files

**Status**: Planned
**Priority**: Low-Medium
**Complexity**: Medium

### Description
Speakeasy supports custom JSON configuration files that control the emulated environment. For honeypot use, custom configs could improve detection by presenting environments that malware expects.

### Implementation Notes

1. Create dionaea-specific Speakeasy config at `conf/speakeasy_config.json`:

```json
{
    "config_version": "1.1.0",
    "timeout": 60,
    "max_api_count": 30000,

    "os_ver": {
        "major": 10,
        "minor": 0,
        "build": 19041
    },

    "hostname": "DESKTOP-HONEYPOT",

    "user": {
        "name": "Administrator",
        "is_admin": true
    },

    "env": {
        "COMPUTERNAME": "DESKTOP-HONEYPOT",
        "USERNAME": "Administrator",
        "TEMP": "C:\\Windows\\Temp",
        "SYSTEMROOT": "C:\\Windows"
    },

    "network": {
        "dns": {
            "names": {
                "update.microsoft.com": "93.184.216.34",
                "download.windowsupdate.com": "93.184.216.34"
            }
        },
        "http": {
            "handlers": [
                {
                    "uri": "/malware.exe",
                    "data": "base64_encoded_fake_payload"
                }
            ]
        }
    },

    "filesystem": {
        "handlers": [
            {
                "mode": "full_path",
                "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "data": "127.0.0.1 localhost\n"
            },
            {
                "mode": "by_ext",
                "ext": ".exe",
                "data": "base64_encoded_fake_exe"
            }
        ]
    },

    "processes": [
        {
            "name": "explorer.exe",
            "path": "C:\\Windows\\explorer.exe",
            "pid": 1234,
            "is_main_exe": true
        },
        {
            "name": "chrome.exe",
            "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "pid": 5678
        }
    ]
}
```

2. Update `SpeakeasyShellcodeHandler.__init__` to load config:

```python
def __init__(self, path: str, config: dict[str, Any] | None = None) -> None:
    # ...

    # Load Speakeasy configuration
    config_path = self.config.get('config_file',
                                  '/opt/dionaea/etc/dionaea/speakeasy_config.json')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            self.speakeasy_config = json.load(f)
            logger.info("Loaded Speakeasy config from %s", config_path)
    else:
        self.speakeasy_config = None
```

3. Pass config to Speakeasy:

```python
se = speakeasy.Speakeasy(logger=logger, config=self.speakeasy_config or config)
```

### Benefits
- Simulate specific Windows versions targeted by malware
- Provide fake DNS/HTTP responses
- Mock expected files/registry keys
- Present realistic process environment

---

## 7. Memory Tracing for Advanced Analysis

**Status**: Planned
**Priority**: Low
**Complexity**: Low

### Description
Speakeasy can log all memory access (reads/writes/executions) to each memory block. This is useful for detecting:
- PEB walking (Process Environment Block parsing)
- Export table parsing
- Hooking attempts
- Memory scanning

### Implementation Notes

Add configuration option to enable memory tracing:

```yaml
# conf/services/speakeasy.yaml
memory_tracing: false  # High performance impact, disabled by default
```

Enable in config when needed:

```python
config = {
    'timeout': self.timeout,
    'max_api_count': 30000,
}

# Enable memory tracing if configured
if self.config.get('memory_tracing', False):
    config['analysis'] = {
        'memory_tracing': True
    }
```

Process memory access events:

```python
mem_access = ep.get('mem_access', [])
for access in mem_access:
    tag = access.get('tag')
    base = access.get('base')
    reads = access.get('reads', 0)
    writes = access.get('writes', 0)
    execs = access.get('execs', 0)

    # Detect suspicious patterns
    if 'PEB' in tag and reads > 0:
        logger.info("PEB access detected at 0x%x (%d reads)", base, reads)

    if tag.startswith('emu.module') and reads > 100:
        logger.info("Heavy module parsing at %s (possible export walking)", tag)
```

### Performance Impact
Memory tracing significantly slows emulation. Only enable for specific investigations or high-value targets.

### Benefits
- Detect shellcode techniques (PEB walking, export parsing)
- Identify hooking attempts
- Track memory scanning behavior
- Deeper behavioral analysis

---

## 8. Module Directory for Export Parsing

**Status**: Planned
**Priority**: Low
**Complexity**: Medium

### Description
Some advanced shellcode manually parses PE export tables instead of using GetProcAddress. Speakeasy can load real Windows DLLs to provide accurate export tables for parsing.

### Implementation Notes

1. Create module directory structure:

```
/opt/dionaea/var/speakeasy/modules/
├── x86/
│   ├── kernel32.dll
│   ├── ntdll.dll
│   ├── ws2_32.dll
│   └── advapi32.dll
└── x64/
    ├── kernel32.dll
    ├── ntdll.dll
    ├── ws2_32.dll
    └── advapi32.dll
```

2. Configure in Speakeasy config:

```json
{
    "modules": {
        "modules_always_exist": true,
        "module_directory_x86": "/opt/dionaea/var/speakeasy/modules/x86",
        "module_directory_x64": "/opt/dionaea/var/speakeasy/modules/x64"
    }
}
```

3. Alternatively, pass via runtime config:

```python
config = {
    'timeout': self.timeout,
    'max_api_count': 30000,
    'modules': {
        'module_directory_x86': '/opt/dionaea/var/speakeasy/modules/x86',
        'module_directory_x64': '/opt/dionaea/var/speakeasy/modules/x64'
    }
}
```

### Security Considerations
- Only use DLLs from trusted sources
- Consider extracting DLLs from Windows VMs in isolated environment
- Do not distribute Windows DLLs (licensing issues)
- Document acquisition process for users

### Benefits
- Support shellcode that manually parses exports
- More accurate emulation of real Windows environment
- Better handling of advanced shellcode techniques

---

## Implementation Priority

Recommended order of implementation:

1. **#5 - Extract Additional IOCs** (Medium priority, low complexity)
   - Immediate value with minimal effort
   - Dropped files and process events are valuable IOCs

2. **#7 - Memory Tracing** (Low priority, low complexity)
   - Easy to add as optional feature
   - Useful for specific investigations

3. **#6 - Custom Configuration** (Medium priority, medium complexity)
   - Good for tailoring environment to specific threats
   - Requires maintenance of config files

4. **#8 - Module Directory** (Low priority, medium complexity)
   - Only needed for advanced shellcode
   - Requires acquiring and distributing DLL files
   - Legal/licensing considerations

---

## Testing Recommendations

When implementing these improvements:

1. Test with known shellcode samples (Metasploit, etc.)
2. Verify performance impact (especially memory tracing)
3. Check that new incidents are properly handled by existing handlers
4. Monitor false positive rates
5. Document any new configuration options in main dionaea docs

---

## References

- Speakeasy Documentation: https://github.com/mandiant/speakeasy
- Speakeasy Configuration Guide: `doc/configuration.md` in speakeasy repo
- Speakeasy Reporting Format: `doc/reporting.md` in speakeasy repo
- Mandiant Blog: https://cloud.google.com/blog/topics/threat-intelligence/emulation-of-malicious-shellcode-with-speakeasy/
