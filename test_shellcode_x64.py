#!/usr/bin/env python3
"""
Test x86-64 shellcode detection by sending sample to dionaea HTTP port
"""
import socket
import time

# x86-64 shellcode with GetPC pattern
# This is a simple x64 shellcode for testing detection:
# - GetPC sequence: call $+5; pop rax (E8 00 00 00 00 58)
# - Followed by NOPs and safe instructions for testing
#
# NOTE: This shellcode is intentionally simple for DETECTION TESTING.
# It will likely crash during emulation (invalid_read) because it doesn't
# have proper API resolution or memory setup. The important test is:
#   1. C detector finds the x86-64 GetPC pattern ✓
#   2. Python receives arch="x86_64" ✓
#   3. Speakeasy is invoked in x64 mode ✓
#
# For real working x64 shellcode, use msfvenom:
#   msfvenom -p windows/x64/exec CMD=calc.exe -f python
#
shellcode_x64 = bytes([
    # GetPC: call $+5; pop rax (THE DETECTION PATTERN WE'RE TESTING)
    0xE8, 0x00, 0x00, 0x00, 0x00,    # call $+5
    0x58,                              # pop rax (rax now has address after this instruction)

    # Some x64 instructions to show this is 64-bit code
    0x48, 0x83, 0xE4, 0xF0,            # and rsp, -16 (stack alignment)
    0x48, 0x31, 0xC9,                  # xor rcx, rcx
    0x48, 0x31, 0xD2,                  # xor rdx, rdx
    0x4D, 0x31, 0xC0,                  # xor r8, r8
    0x4D, 0x31, 0xC9,                  # xor r9, r9

    # REX.W prefix examples (characteristic of x64)
    0x48, 0x89, 0xE5,                  # mov rbp, rsp
    0x48, 0x83, 0xEC, 0x20,            # sub rsp, 0x20 (shadow space)

    # NOPs to pad
    0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90,

    # Return
    0xC3,                              # ret
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
        print("  ✓ 'Found x86-64 GetPC pattern at offset 0'")
        print("  ✓ 'Shellcode detected at offset 0 (arch: x86_64)'")
        print("  ✓ 'Analyzing shellcode: N bytes (arch: x86_64)'")
        print("  ✓ 'Starting Speakeasy emulation (arch: x86_64)'")
        print("\nNOTE: Emulation may crash with 'invalid_read' - this is EXPECTED.")
        print("The test shellcode is intentionally minimal to verify DETECTION,")
        print("not full emulation. The important part is detecting the x64 pattern.")

    except Exception as e:
        print(f"Error: {e}")
        return False

    return True

if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    test_x64_shellcode(host, port)
