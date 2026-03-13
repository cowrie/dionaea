..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>

    SPDX-License-Identifier: AGPL-3.0-only

IP stack
========

The custom IP stack provides honeyd-style OS fingerprint emulation by operating
a userspace TCP/IP stack on a TUN device. Instead of relying on the kernel's
TCP/IP stack (which has its own OS fingerprint), dionaea crafts every packet
— SYN-ACKs, RSTs, ICMP replies — with parameters that match a chosen OS
personality from the nmap fingerprint database.

This defeats nmap OS detection (``nmap -O``) and makes the honeypot appear as
a real Windows, Linux, or FreeBSD host.

How it works
------------

.. code-block:: text

    Network traffic
         │
         ▼
    ┌─────────────┐     ┌──────────────┐     ┌────────────────┐
    │  TUN Device  │────▶│  IP Demuxer  │────▶│  TCP Engine    │
    │  (raw pkts)  │◀────│  (IPv4)      │◀────│  (per-conn SM) │
    └─────────────┘     │              │     └────────────────┘
                        │              │────▶│  UDP Handler   │
                        │              │◀────│  (ICMP unreach)│
                        │              │     └────────────────┘
                        │              │────▶│  ICMP Handler  │
                        │              │◀────│  (echo reply)  │
                        └──────────────┘     └────────────────┘
                               │
                        ┌──────────────┐
                        │  Personality  │  ← nmap-os-db
                        │  Engine       │  ← TTL, window, ISN,
                        │              │    DF, options, ICMP
                        └──────────────┘

The kernel never sees the packets. Traffic destined for the honeypot IP range
is routed to a TUN interface (``honeypot0`` by default), delivered to userspace
as raw IP packets, and every response is crafted by the personality engine.

What nmap probes are simulated
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following nmap OS detection probes are handled:

- **SEQ** — ISN generation pattern (GCD, predictability index)
- **T1** (SYN to open port) — SYN-ACK with personality-correct window, TTL, DF, TCP options
- **T2-T4** (unusual TCP flag combinations) — per-personality response or silence
- **T5-T7** (SYN/ACK to closed port) — RST with correct sequence/ack behavior
- **U1** (UDP to closed port) — ICMP Port Unreachable with correct TTL, DF, IP total length, UN bytes
- **IE** (ICMP echo) — Echo Reply with correct DF bit and code field handling
- **ECN** (Explicit Congestion Notification) — per-personality ECN support signaling

Prerequisites
-------------

**Operating system:** Linux (TUN device support required).

**nmap fingerprint database:** The ``nmap-os-db`` file ships with nmap and
contains ~5,800 OS fingerprints.

.. code-block:: console

    # Debian/Ubuntu
    sudo apt-get install nmap

    # RHEL/Fedora
    sudo dnf install nmap

    # Verify the database exists
    ls -l /usr/share/nmap/nmap-os-db

If nmap is not installed, you can download just the database file::

    curl -O https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db

**Kernel module:** The ``tun`` kernel module must be loaded:

.. code-block:: console

    sudo modprobe tun
    ls /dev/net/tun   # should exist

**Permissions:** Creating a TUN device requires ``CAP_NET_ADMIN`` or root.
Dionaea already requires root for binding to privileged ports, so this adds
no new requirement.


Installation
------------

The ipstack crate is built as part of the standard dionaea workspace::

    cargo build --release

No additional dependencies beyond what the main build requires, except:

- ``tun-rs`` (compiled automatically via Cargo)
- ``etherparse`` (compiled automatically via Cargo)
- ``nmap`` (or just its ``nmap-os-db`` file) on the host


Configuration
-------------

Add an ``[ipstack]`` section to your ``dionaea.toml`` or use a dedicated
config file at ``conf/services/ipstack.toml``.

Minimal configuration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

    [ipstack]
    enabled = true
    tcp_ports = [22, 80, 135, 139, 443, 445, 3389]
    udp_ports = [137, 161]

This uses all defaults: TUN device ``honeypot0`` at ``10.0.0.1/24``,
personality ``Linux 3.2 - 4.9``, nmap-os-db from ``/usr/share/nmap/nmap-os-db``.

Full configuration
~~~~~~~~~~~~~~~~~~

.. code-block:: toml

    [ipstack]
    enabled = true

    # TCP ports the honeypot considers "open" (SYN-ACK response)
    tcp_ports = [22, 80, 135, 139, 443, 445, 3389]

    # UDP ports considered "open" (no ICMP unreachable)
    udp_ports = [137, 161]

    [ipstack.tun]
    # TUN device name (empty string for kernel auto-assign)
    name = "honeypot0"

    # IP address assigned to the TUN interface
    address = "10.0.0.1"

    # Network mask
    netmask = "255.255.255.0"

    # MTU (default 1500)
    mtu = 1500

    [ipstack.personality]
    # Path to nmap-os-db fingerprint database
    nmap_os_db = "/usr/share/nmap/nmap-os-db"

    # OS fingerprint name (substring match against nmap-os-db)
    # Examples:
    #   "Windows 10 (1903)"
    #   "Linux 3.2 - 4.9"
    #   "Linux 5.4"
    #   "FreeBSD 12.0-RELEASE"
    #   "Windows Server 2019"
    name = "Windows 10 (1903)"

Configuration reference
~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 15 15 40

   * - Key
     - Type
     - Default
     - Description
   * - ``enabled``
     - bool
     - ``false``
     - Enable the custom IP stack
   * - ``tcp_ports``
     - list[int]
     - ``[]``
     - TCP ports that appear "open" (respond with SYN-ACK)
   * - ``udp_ports``
     - list[int]
     - ``[]``
     - UDP ports that appear "open" (no ICMP unreachable)
   * - ``tun.name``
     - string
     - ``"honeypot0"``
     - TUN device name (empty for auto-assign)
   * - ``tun.address``
     - IPv4
     - ``10.0.0.1``
     - IP address for the TUN interface
   * - ``tun.netmask``
     - IPv4
     - ``255.255.255.0``
     - Network mask
   * - ``tun.mtu``
     - int
     - ``1500``
     - Maximum transmission unit
   * - ``personality.nmap_os_db``
     - path
     - ``/usr/share/nmap/nmap-os-db``
     - Path to the nmap fingerprint database file
   * - ``personality.name``
     - string
     - ``"Linux 3.2 - 4.9"``
     - OS personality name (substring match in nmap-os-db)


Running
-------

1. **Start dionaea** with the ipstack enabled in your config:

   .. code-block:: console

       sudo dionaea -c /opt/dionaea/conf/dionaea.toml

   You should see log output like::

       INFO loaded OS personality personality="Windows 10 (1903)" ttl=128 df=true window=8192
       INFO TUN device created name="honeypot0" address=10.0.0.1 netmask=255.255.255.0 mtu=1500
       INFO TCP port open port=445
       INFO TCP port open port=3389

2. **Set up routing** so traffic reaches the TUN device. The exact method
   depends on your network topology:

   **Single-host deployment** (honeypot IPs on same machine):

   .. code-block:: console

       # Route a subnet to the TUN device
       sudo ip route add 10.0.0.0/24 dev honeypot0

   **Network deployment** (honeypot IPs on a different subnet):

   .. code-block:: console

       # On the upstream router, route the honeypot subnet to the dionaea host
       # Then on the dionaea host:
       sudo ip route add 192.168.50.0/24 dev honeypot0

       # Enable IP forwarding if needed
       sudo sysctl -w net.ipv4.ip_forward=1

   **Bridge/VLAN deployment:**

   .. code-block:: console

       # Add the honeypot IP as a secondary address on the TUN
       sudo ip addr add 192.168.1.100/32 dev honeypot0

       # Use ARP proxy or static ARP on the gateway
       sudo ip neigh add proxy 192.168.1.100 dev eth0

3. **Verify** the TUN device is up:

   .. code-block:: console

       ip link show honeypot0
       ip addr show honeypot0
       ip route | grep honeypot0

4. **Test with nmap:**

   .. code-block:: console

       # OS detection scan against the honeypot IP
       sudo nmap -O 10.0.0.1

       # Expected output should show the configured personality, e.g.:
       # OS details: Windows 10 (1903)


Choosing a personality
----------------------

To list available personalities, search the nmap-os-db file:

.. code-block:: console

    # List all Windows 10 fingerprints
    grep '^Fingerprint' /usr/share/nmap/nmap-os-db | grep -i 'windows 10'

    # List all Linux fingerprints
    grep '^Fingerprint' /usr/share/nmap/nmap-os-db | grep -i 'linux'

    # List all fingerprints (there are ~5800)
    grep -c '^Fingerprint' /usr/share/nmap/nmap-os-db

Common choices:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Personality
     - Use case
   * - ``Windows 10 (1903)``
     - Modern Windows workstation (TTL 128, DF set)
   * - ``Windows Server 2019``
     - Windows server role
   * - ``Linux 3.2 - 4.9``
     - Generic modern Linux (TTL 64, DF set)
   * - ``Linux 5.4``
     - Recent Linux kernel
   * - ``FreeBSD 12.0-RELEASE``
     - BSD system (TTL 64, different TCP options)
   * - ``Windows 7 Professional 7601 Service Pack 1``
     - Legacy Windows (common target for EternalBlue)

The ``name`` field uses substring matching, so ``"Windows 10"`` matches the
first fingerprint containing that string. Use the full name for precision.


Kernel RST behavior
-------------------

A common concern with userspace TCP stacks is the kernel sending RST packets
for connections it doesn't know about. The TUN device approach avoids this
entirely:

.. code-block:: text

    With raw sockets (BAD):
      Network → kernel TCP stack → "no socket for this!" → RST sent
      Requires: iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

    With TUN device (GOOD):
      Network → routing table → tun0 → /dev/net/tun fd → our code
      Kernel TCP stack never sees the packets → no RSTs

No iptables rules, no kernel modifications, no interference.


Troubleshooting
---------------

**"failed to create TUN device: Operation not permitted"**
    Run dionaea as root or with ``CAP_NET_ADMIN``:

    .. code-block:: console

        sudo setcap cap_net_admin+ep /opt/dionaea/bin/dionaea

**"personality not found in nmap-os-db: ..."**
    The personality name must be a substring of a ``Fingerprint`` line in
    nmap-os-db. Check available names::

        grep '^Fingerprint' /usr/share/nmap/nmap-os-db | grep -i '<your search>'

**"TUN read error" or no traffic reaching the stack**
    Verify routing is set up::

        ip route get 10.0.0.1   # should show "dev honeypot0"
        sudo tcpdump -i honeypot0 -n  # should show incoming packets

**nmap still shows "Too many fingerprints match" or wrong OS**
    Ensure the personality has all probe fields populated. Some nmap-os-db
    entries are sparse. Try a well-populated fingerprint like
    ``"Linux 3.2 - 4.9"`` or ``"Windows 10 (1903)"``.
