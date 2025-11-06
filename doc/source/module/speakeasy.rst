Speakeasy Shellcode Detection
==============================

Overview
--------

Dionaea uses Mandiant's Speakeasy framework to detect and analyze shellcode in
captured network traffic. The integration provides a two-stage detection and
analysis pipeline:

1. **Fast C-based detection** - Scans incoming data streams for GetPC patterns
   commonly used in position-independent shellcode
2. **Comprehensive Python analysis** - Uses Speakeasy to emulate detected
   shellcode and identify malicious behavior

What Speakeasy Detects
-----------------------

The Speakeasy integration can identify:

* **File downloads** - URLDownloadToFile and similar API calls
* **Bind shells** - Socket operations that listen for incoming connections
* **Reverse shells** - Outbound connections that provide shell access
* **Process execution** - CreateProcess, WinExec, system() calls
* **Registry manipulation** - RegOpenKey, RegSetValue operations
* **Network activity** - Socket creation, connections, data transmission

Detection Process
-----------------

When data arrives on a monitored protocol:

1. **Pattern Detection** (C module)

   * Scans the incoming byte stream for GetPC patterns
   * GetPC patterns include:

     - CALL/POP sequences (0xE8 opcode)
     - FNSTENV instructions (0xD9 opcode)

   * If a pattern is found, attempts to execute code from that offset
   * Successful execution indicates probable shellcode

2. **Behavior Analysis** (Python handler)

   * Emulates the detected shellcode using Speakeasy
   * Tracks Windows API calls made during emulation
   * Identifies malicious patterns:

     - Downloads: URLDownloadToFile, URLOpenURL
     - Shells: socket → bind → listen → accept → CreateProcess
     - Execution: CreateProcess with cmd.exe or powershell.exe

3. **Logging**

   * Logs detected shellcode with offset and size
   * Records API call sequences
   * Identifies specific malicious behaviors
   * Stores shellcode samples for analysis

Enabling Speakeasy
------------------

Speakeasy detection is **enabled by default** for the following protocols:

* SMB (smbd)
* EPMAPPER (epmapper)
* NFQMIRROR (nfqmirrord)
* MSSQL (mssqld)

To enable for additional protocols, edit ``dionaea.cfg``:

.. code-block:: ini

   [processor.filter_speakeasy]
   name=filter
   config.allow.0.types=accept
   config.allow.0.protocols=smbd,epmapper,nfqmirrord,mssqld,httpd
   next=speakeasy

   [processor.speakeasy]
   name=speakeasy

Configuration
-------------

The Speakeasy handler can be configured via ``ihandlers-enabled/speakeasy.yaml``:

.. code-block:: yaml

   - name: speakeasy
     config:
       max_instructions: 1000000  # Maximum instructions to emulate
       timeout: 60                # Emulation timeout in seconds

Adjusting these values affects analysis thoroughness vs. performance:

* Higher ``max_instructions`` allows more complex shellcode to complete
* Lower ``timeout`` prevents long-running emulation from blocking
* Default values work well for most shellcode samples

Disabling Speakeasy
-------------------

To disable shellcode detection:

1. Remove ``speakeasy`` from the modules list in ``dionaea.cfg``:

   .. code-block:: ini

      modules=curl,python
      processors=filter_streamdumper

2. Or disable just the Python handler by removing the symlink:

   .. code-block:: bash

      rm /opt/dionaea/etc/dionaea/ihandlers-enabled/speakeasy.yaml

Log Output
----------

When shellcode is detected, you'll see log entries like:

.. code-block:: text

   [INFO] Shellcode detected at offset 110 (stream size: 470)
   [INFO] Analyzing shellcode at offset 110 (378 bytes total)
   [INFO] Speakeasy emulation completed: 256 instructions executed
   [INFO] Detected download: http://example.com/malware.exe
   [INFO] Download method: URLDownloadToFile

The logs provide:

* Detection offset in the data stream
* Shellcode size
* Number of instructions emulated
* Identified malicious behaviors
* Specific URLs, file paths, or commands

Performance Considerations
--------------------------

Shellcode detection runs in a thread pool to avoid blocking connection handling:

* **Detection** (C module) - Very fast, < 1ms typical
* **Emulation** (Python/Speakeasy) - Slower, 10-100ms typical
* **Thread pool** - Prevents blocking other connections

For high-traffic deployments:

* Detection happens automatically on all enabled protocols
* Emulation runs in background threads
* Failed emulation doesn't affect connection handling
* Timeout prevents runaway emulation

Troubleshooting
---------------

**Shellcode not detected**

* Check that the protocol is in the filter configuration
* Verify the data contains actual shellcode (GetPC patterns)
* Check logs for "No GetPC patterns found"

**Emulation errors**

* Speakeasy may fail on certain shellcode types
* Check logs for specific error messages
* Not all shellcode can be successfully emulated

**High CPU usage**

* Lower ``max_instructions`` in configuration
* Reduce ``timeout`` value
* Disable for high-traffic protocols if needed

Technical Details
-----------------

The implementation uses:

* **libemu wrapper** - Minimal C library wrapping Unicorn Engine
* **GetPC detection** - Pattern matching for position-independent code
* **Unicorn 1.0.2** - CPU emulation engine (via pip)
* **Speakeasy** - Mandiant's Windows API emulation framework

The C detector provides fast initial scanning, while Speakeasy performs deep
analysis only when shellcode is actually detected. This hybrid approach
provides comprehensive detection with minimal performance impact.

Further Reading
---------------

* Speakeasy project: https://github.com/mandiant/speakeasy
* Unicorn Engine: https://www.unicorn-engine.org/
* GetPC techniques: https://en.wikipedia.org/wiki/Shellcode#Locating_shellcode
