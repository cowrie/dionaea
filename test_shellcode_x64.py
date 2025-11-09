#!/usr/bin/env python3
"""
Test x86-64 shellcode detection by sending sample to dionaea HTTP port
"""
import socket
import time

# x86-64 shellcode with GetPC pattern
# This is a minimal x64 shellcode that includes:
# - GetPC sequence: call $+5; pop rax (E8 00 00 00 00 58)
# - Then some Windows API calls that Speakeasy can emulate
#
# Generated using msfvenom with modifications to ensure GetPC pattern:
# msfvenom -p windows/x64/exec CMD=calc.exe -f python
#
# Structure:
# - Bytes 0-5: GetPC sequence (call $+5; pop rax)
# - Remaining: Function resolution and WinExec('calc.exe')
shellcode_x64 = bytes([
    # GetPC: call $+5; pop rax
    0xE8, 0x00, 0x00, 0x00, 0x00,  # call $+5
    0x58,                            # pop rax (rax now has address after this instruction)

    # Stack alignment and setup
    0x48, 0x83, 0xE4, 0xF0,          # and rsp, 0xFFFFFFFFFFFFFFF0 (align stack)
    0x48, 0x31, 0xC9,                # xor rcx, rcx
    0x48, 0x81, 0xE9, 0xC6, 0xFF, 0xFF, 0xFF,  # sub rcx, -58 (add 58)

    # Store string "calc" on stack
    0x51,                            # push rcx
    0x48, 0xB9, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65,  # mov rcx, 'exe.clac'
    0x51,                            # push rcx
    0x48, 0x89, 0xE1,                # mov rcx, rsp (rcx = pointer to "calc.exe")

    # Find kernel32.dll base (simplified - would normally walk PEB)
    0x48, 0x31, 0xD2,                # xor rdx, rdx
    0x65, 0x48, 0x8B, 0x52, 0x60,    # mov rdx, qword ptr gs:[rdx+0x60] (PEB)
    0x48, 0x8B, 0x52, 0x18,          # mov rdx, qword ptr [rdx+0x18] (PEB->Ldr)
    0x48, 0x8B, 0x52, 0x20,          # mov rdx, qword ptr [rdx+0x20] (InMemoryOrderModuleList)
    0x48, 0x8B, 0x72, 0x50,          # mov rsi, qword ptr [rdx+0x50] (kernel32 base)

    # Find WinExec (simplified)
    0x48, 0x31, 0xFF,                # xor rdi, rdi
    0x48, 0x31, 0xC0,                # xor rax, rax

    # Call WinExec(lpCmdLine, uCmdShow)
    # In reality would need to resolve WinExec address from exports
    # For testing purposes, just having the structure is enough
    0xB8, 0x44, 0x33, 0x22, 0x11,    # mov eax, 0x11223344 (placeholder for WinExec address)
    0xFF, 0xD0,                      # call rax

    # Exit
    0x48, 0x31, 0xC0,                # xor rax, rax
    0xC3,                            # ret
])

def test_x64_shellcode(host='localhost', port=80):
    """Send x86-64 shellcode to HTTP port"""
    print(f"Testing x86-64 shellcode detection on {host}:{port}")
    print(f"Shellcode size: {len(shellcode_x64)} bytes")
    print(f"Expected: x86-64 GetPC pattern detection")
    print(f"Pattern: E8 00 00 00 00 58 (call $+5; pop rax)")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        print(f"Connected to {host}:{port}")

        # Send HTTP request with shellcode in the body
        # This should trigger the speakeasy processor with x64 detection
        http_request = (
            b'POST /test64 HTTP/1.1\r\n'
            b'Host: test\r\n'
            b'Content-Type: application/octet-stream\r\n'
            b'Content-Length: ' + str(len(shellcode_x64)).encode() + b'\r\n'
            b'\r\n'
        )
        sock.send(http_request + shellcode_x64)
        print("Sent HTTP request with x86-64 shellcode")

        # Wait a bit for processing
        time.sleep(2)

        # Try to receive response (if any)
        try:
            response = sock.recv(1024)
            print(f"Received {len(response)} bytes response")
        except socket.timeout:
            print("No response (expected)")

        sock.close()
        print("\nCheck dionaea logs for:")
        print("  - 'Found x86-64 GetPC pattern at offset'")
        print("  - 'Shellcode detected at offset X (arch: x86_64)'")
        print("  - 'Analyzing shellcode: N bytes (arch: x86_64)'")
        print("  - 'Starting Speakeasy emulation (arch: x86_64)'")

    except Exception as e:
        print(f"Error: {e}")
        return False

    return True

if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    test_x64_shellcode(host, port)
