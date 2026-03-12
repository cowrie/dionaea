// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Integration tests for SMB and EPMAP (DCE/RPC) protocols.
// ABOUTME: Verifies negotiate response (SMB) and DCERPC bind_ack (EPMAP).

use std::sync::Arc;
use std::time::Duration;

use dionaea::config;
use dionaea::connection::limits::ConnectionLimits;
use dionaea::connection::ConnectionRegistry;
use dionaea::runtime;
use pyo3::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

fn test_config() -> config::Config {
    config::load_from_str(
        r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
level = "debug"
[modules]
"#,
    )
    .expect("test config")
}

/// Build a minimal SMB negotiate request packet (NBT framed).
///
/// Requests the "NT LM 0.12" dialect, which is the only one SMBv1 needs.
fn build_smb_negotiate_request() -> Vec<u8> {
    // SMB Header (32 bytes)
    let mut smb_header = Vec::new();
    smb_header.extend_from_slice(b"\xffSMB"); // Start
    smb_header.push(0x72); // Command = SMB_COM_NEGOTIATE
    smb_header.extend_from_slice(&[0u8; 4]); // Status
    smb_header.push(0x00); // Flags
    smb_header.extend_from_slice(&[0u8; 2]); // Flags2
    smb_header.extend_from_slice(&[0u8; 2]); // PidHigh
    smb_header.extend_from_slice(&[0u8; 8]); // SecurityFeatures
    smb_header.extend_from_slice(&[0u8; 2]); // Reserved
    smb_header.extend_from_slice(&[0u8; 2]); // Tid
    smb_header.extend_from_slice(&[0u8; 2]); // Pid
    smb_header.extend_from_slice(&[0u8; 2]); // Uid
    smb_header.extend_from_slice(&[0u8; 2]); // Mid

    // Negotiate payload: WordCount=0, ByteCount=12, BufferFormat=0x02, "NT LM 0.12\0"
    let dialect = b"NT LM 0.12\0";
    let byte_count: u16 = 1 + dialect.len() as u16; // BufferFormat byte + dialect string
    let mut payload = Vec::new();
    payload.push(0x00); // WordCount = 0
    payload.extend_from_slice(&byte_count.to_le_bytes()); // ByteCount
    payload.push(0x02); // BufferFormat
    payload.extend_from_slice(dialect);

    let smb_data = [smb_header, payload].concat();
    let smb_len = smb_data.len();

    // NBT Session header: TYPE=0x00, RESERVED=0, LENGTH (17-bit)
    let mut packet = Vec::new();
    packet.push(0x00); // TYPE = Session Message
    packet.push(0x00); // RESERVED + high bit of length
    packet.push((smb_len >> 8) as u8);
    packet.push(smb_len as u8);
    packet.extend_from_slice(&smb_data);
    packet
}

/// Build a DCERPC bind request for a given interface UUID.
///
/// Uses NDR32 transfer syntax.
fn build_dcerpc_bind(interface_uuid: &[u8; 16], call_id: u32) -> Vec<u8> {
    // NDR32 transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
    let ndr32_uuid: [u8; 16] = [
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
        0x48, 0x60,
    ];

    // Bind body (after DCERPC header):
    //   MaxTransmitFrag (2) + MaxReceiveFrag (2) + AssocGroup (4) +
    //   NumCtxItems (1) + FixGap (3) + CtxItem (44)
    let mut bind_body = Vec::new();
    bind_body.extend_from_slice(&5840u16.to_le_bytes()); // MaxTransmitFrag
    bind_body.extend_from_slice(&5840u16.to_le_bytes()); // MaxReceiveFrag
    bind_body.extend_from_slice(&0u32.to_le_bytes()); // AssocGroup
    bind_body.push(1); // NumCtxItems
    bind_body.extend_from_slice(&[0u8; 3]); // FixGap

    // CtxItem: ContextID(2) + NumTransItems(1) + FixGap(1) + UUID(16) +
    //          InterfaceVer(2) + InterfaceVerMinor(2) + TransferSyntax(16) + TransferSyntaxVersion(4)
    bind_body.extend_from_slice(&0u16.to_le_bytes()); // ContextID
    bind_body.push(1); // NumTransItems
    bind_body.push(0); // FixGap
    bind_body.extend_from_slice(interface_uuid); // Interface UUID
    bind_body.extend_from_slice(&0u16.to_le_bytes()); // InterfaceVer
    bind_body.extend_from_slice(&0u16.to_le_bytes()); // InterfaceVerMinor
    bind_body.extend_from_slice(&ndr32_uuid); // TransferSyntax (NDR32)
    bind_body.extend_from_slice(&2u32.to_le_bytes()); // TransferSyntaxVersion

    let frag_len: u16 = 16 + bind_body.len() as u16; // DCERPC header (16) + body

    // DCERPC Header (16 bytes)
    let mut packet = Vec::new();
    packet.push(5); // Version
    packet.push(0); // VersionMinor
    packet.push(11); // PacketType = bind
    packet.push(0x03); // PacketFlags (first_frag | last_frag)
    packet.extend_from_slice(&0x00000010u32.to_le_bytes()); // DataRepresentation (LE)
    packet.extend_from_slice(&frag_len.to_le_bytes()); // FragLen
    packet.extend_from_slice(&0u16.to_le_bytes()); // AuthLen
    packet.extend_from_slice(&call_id.to_le_bytes()); // CallID
    packet.extend_from_slice(&bind_body);
    packet
}

/// Build a DCERPC bind request for the ATSVC service.
fn build_dcerpc_bind_request() -> Vec<u8> {
    // ATSVC UUID: 1ff70682-0a51-30e8-076d-740be8cee98b (little-endian wire format)
    let interface_uuid: [u8; 16] = [
        0x82, 0x06, 0xf7, 0x1f, 0x51, 0x0a, 0xe8, 0x30, 0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce,
        0xe9, 0x8b,
    ];
    build_dcerpc_bind(&interface_uuid, 1)
}

/// Build a DCERPC request packet with given opnum and stub data.
fn build_dcerpc_request(opnum: u16, stub: &[u8], call_id: u32) -> Vec<u8> {
    // Request body: AllocHint(4) + ContextID(2) + OpNum(2)
    let mut body = Vec::new();
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // AllocHint
    body.extend_from_slice(&0u16.to_le_bytes()); // ContextID
    body.extend_from_slice(&opnum.to_le_bytes()); // OpNum
    body.extend_from_slice(stub);

    let frag_len: u16 = 16 + body.len() as u16;

    let mut packet = Vec::new();
    packet.push(5); // Version
    packet.push(0); // VersionMinor
    packet.push(0); // PacketType = request
    packet.push(0x03); // PacketFlags (first_frag | last_frag)
    packet.extend_from_slice(&0x00000010u32.to_le_bytes()); // DataRepresentation (LE)
    packet.extend_from_slice(&frag_len.to_le_bytes()); // FragLen
    packet.extend_from_slice(&0u16.to_le_bytes()); // AuthLen
    packet.extend_from_slice(&call_id.to_le_bytes()); // CallID
    packet.extend_from_slice(&body);
    packet
}

/// Build NDR stub data for ept_map: request tower for a given interface UUID.
fn build_ept_map_stub(interface_uuid_le: &[u8; 16]) -> Vec<u8> {
    // NDR32 transfer syntax UUID (little-endian wire bytes)
    let ndr32_uuid: [u8; 16] = [
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
        0x48, 0x60,
    ];

    // Build input tower (5 floors)
    let mut tower = Vec::new();
    tower.extend_from_slice(&5u16.to_le_bytes()); // Floor count

    // Floor 1: Interface UUID (LHS: proto_id=0x0D + UUID + version)
    let mut lhs1 = vec![0x0D]; // PROTO_ID_UUID
    lhs1.extend_from_slice(interface_uuid_le);
    lhs1.extend_from_slice(&3u16.to_le_bytes()); // major version
    tower.extend_from_slice(&(lhs1.len() as u16).to_le_bytes());
    tower.extend_from_slice(&lhs1);
    tower.extend_from_slice(&2u16.to_le_bytes()); // RHS length
    tower.extend_from_slice(&0u16.to_le_bytes()); // minor version

    // Floor 2: NDR transfer syntax
    let mut lhs2 = vec![0x0D];
    lhs2.extend_from_slice(&ndr32_uuid);
    lhs2.extend_from_slice(&2u16.to_le_bytes()); // version 2
    tower.extend_from_slice(&(lhs2.len() as u16).to_le_bytes());
    tower.extend_from_slice(&lhs2);
    tower.extend_from_slice(&2u16.to_le_bytes());
    tower.extend_from_slice(&0u16.to_le_bytes());

    // Floor 3: RPC connection-oriented (proto_id=0x0B)
    tower.extend_from_slice(&1u16.to_le_bytes()); // LHS len
    tower.push(0x0B);
    tower.extend_from_slice(&2u16.to_le_bytes()); // RHS len
    tower.extend_from_slice(&0u16.to_be_bytes()); // minor version

    // Floor 4: TCP (proto_id=0x07)
    tower.extend_from_slice(&1u16.to_le_bytes());
    tower.push(0x07);
    tower.extend_from_slice(&2u16.to_le_bytes());
    tower.extend_from_slice(&0u16.to_be_bytes()); // port 0

    // Floor 5: IP (proto_id=0x09)
    tower.extend_from_slice(&1u16.to_le_bytes());
    tower.push(0x09);
    tower.extend_from_slice(&4u16.to_le_bytes());
    tower.extend_from_slice(&[0u8; 4]); // 0.0.0.0

    // NDR encode ept_map parameters:
    // void ept_map(
    //   [in, ptr] UUID* object,              -> NULL pointer
    //   [in, ptr] twr_p_t map_tower,         -> pointer to tower
    //   [in, out] ept_lookup_handle_t* entry_handle, -> 20 bytes zero
    //   [in] unsigned long max_towers,       -> 4
    //   ...
    // )
    let mut stub = Vec::new();
    stub.extend_from_slice(&0u32.to_le_bytes()); // object pointer = NULL
    stub.extend_from_slice(&1u32.to_le_bytes()); // map_tower pointer (non-NULL)
    // entry_handle: attributes(4) + uuid(16) = 20 bytes
    stub.extend_from_slice(&[0u8; 20]);
    stub.extend_from_slice(&4u32.to_le_bytes()); // max_towers

    // Deferred data for map_tower: twr_t = conformant { tower_length, tower_octet_string[] }
    let tower_len = tower.len() as u32;
    stub.extend_from_slice(&tower_len.to_le_bytes()); // max_count (conformant)
    stub.extend_from_slice(&tower_len.to_le_bytes()); // tower_length field
    stub.extend_from_slice(&tower);
    // Pad to 4-byte alignment
    if tower.len() % 4 != 0 {
        stub.extend_from_slice(&vec![0u8; 4 - tower.len() % 4]);
    }

    stub
}

/// Test EPMAP and SMB protocols end-to-end.
///
/// EPMAP: connect, send DCERPC bind, verify bind_ack response.
/// SMB: connect, send negotiate, verify negotiate response.
#[test]
fn test_smb_and_epmap_protocols() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let registry = Arc::new(ConnectionRegistry::new());
    let limits = Arc::new(ConnectionLimits::new(50, 10_000, 70));
    let state = Arc::new(runtime::RuntimeState::new(
        registry.clone(),
        limits.clone(),
        65536,
        test_config(),
        Vec::new(),
    ));
    runtime::init(state.clone());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        let python_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../modules/python")
            .canonicalize()
            .expect("modules/python/ should exist");

        // Start both EPMAP and SMB listeners
        let (epmap_port, smb_port): (u16, u16) = tokio::task::spawn_blocking(move || {
            Python::attach(|py| {
                dionaea::python::loader::load(
                    py,
                    &config::PythonModuleConfig {
                        imports: vec![],
                        service_configs: vec![],
                        ihandler_configs: vec![],
                        python_path: Some(python_path),
                    },
                )
                .expect("loader init");

                let code = r#"
from dionaea.smb import epmapper, smbd

ep = epmapper()
ep.bind('127.0.0.1', 0)
ep.listen()
epmap_port = ep.local.port

sm = smbd()
sm.apply_config()
sm.bind('127.0.0.1', 0)
sm.listen()
smb_port = sm.local.port
"#;
                let c_code = std::ffi::CString::new(code).expect("CString");
                py.run(c_code.as_c_str(), None, None)
                    .expect("SMB/EPMAP setup");

                let ep: u16 = py
                    .eval(c"epmap_port", None, None)
                    .expect("get epmap_port")
                    .extract()
                    .expect("extract epmap_port");
                let sm: u16 = py
                    .eval(c"smb_port", None, None)
                    .expect("get smb_port")
                    .extract()
                    .expect("extract smb_port");
                (ep, sm)
            })
        })
        .await
        .expect("spawn_blocking");

        assert!(epmap_port > 0, "EPMAP listener should bind to a real port");
        assert!(smb_port > 0, "SMB listener should bind to a real port");
        time::sleep(Duration::from_millis(100)).await;

        // --- EPMAP: DCERPC bind ---
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{epmap_port}"))
                .await
                .expect("connect to EPMAP");

            let bind_request = build_dcerpc_bind_request();
            stream
                .write_all(&bind_request)
                .await
                .expect("write DCERPC bind");

            // Read DCERPC bind_ack response
            let mut buf = vec![0u8; 4096];
            let n = time::timeout(Duration::from_secs(3), stream.read(&mut buf))
                .await
                .expect("bind_ack timeout")
                .expect("bind_ack read");

            assert!(n >= 16, "expected at least DCERPC header (16 bytes), got {n}");

            // Verify DCERPC header fields
            assert_eq!(buf[0], 5, "DCERPC Version should be 5");
            assert_eq!(buf[1], 0, "DCERPC VersionMinor should be 0");
            assert_eq!(buf[2], 12, "PacketType should be 12 (bind_ack)");

            // Verify CallID matches (bytes 12-15, little-endian)
            let call_id = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
            assert_eq!(call_id, 1, "CallID should match request");
        }

        // --- EPMAP: ept_map request ---
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{epmap_port}"))
                .await
                .expect("connect to EPMAP for ept_map");

            // Bind to EPM interface first
            // EPM UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa (little-endian wire bytes)
            let epm_uuid: [u8; 16] = [
                0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b,
                0x14, 0xa0, 0xfa,
            ];
            let bind = build_dcerpc_bind(&epm_uuid, 1);
            stream.write_all(&bind).await.expect("write EPM bind");

            let mut buf = vec![0u8; 4096];
            let n = time::timeout(Duration::from_secs(3), stream.read(&mut buf))
                .await
                .expect("EPM bind_ack timeout")
                .expect("EPM bind_ack read");
            assert!(n >= 16, "expected bind_ack, got {n} bytes");
            assert_eq!(buf[2], 12, "expected bind_ack (type 12), got {}", buf[2]);

            // Send ept_map request for SRVSVC
            // SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188 (little-endian wire bytes)
            let srvsvc_uuid: [u8; 16] = [
                0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf,
                0x6e, 0xe1, 0x88,
            ];
            let stub = build_ept_map_stub(&srvsvc_uuid);
            let request = build_dcerpc_request(3, &stub, 2); // opnum 3 = ept_map
            stream
                .write_all(&request)
                .await
                .expect("write ept_map request");

            let mut buf = vec![0u8; 4096];
            let n = time::timeout(Duration::from_secs(3), stream.read(&mut buf))
                .await
                .expect("ept_map response timeout")
                .expect("ept_map response read");

            assert!(n >= 24, "expected DCERPC response, got {n} bytes");
            assert_eq!(buf[0], 5, "DCERPC Version");
            assert_eq!(buf[2], 2, "PacketType should be 2 (response)");

            let call_id = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
            assert_eq!(call_id, 2, "CallID should match request");

            // Stub data starts at offset 24 (16 header + 8 response fields)
            // Parse: entry_handle(20) + num_towers(4) + ...
            // The last 4 bytes of stub should be status (0 = success)
            let stub_data = &buf[24..n];
            assert!(
                stub_data.len() >= 28,
                "stub too short for ept_map response: {} bytes",
                stub_data.len()
            );
            let status = u32::from_le_bytes([
                buf[n - 4],
                buf[n - 3],
                buf[n - 2],
                buf[n - 1],
            ]);
            assert_eq!(status, 0, "ept_map status should be success (0)");

            // num_towers at offset 20 in stub (after 20-byte entry_handle)
            let num_towers =
                u32::from_le_bytes(stub_data[20..24].try_into().expect("4 bytes"));
            assert!(
                num_towers >= 1,
                "expected at least 1 tower for SRVSVC, got {num_towers}"
            );
        }

        // --- SMB: negotiate ---
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{smb_port}"))
                .await
                .expect("connect to SMB");

            let negotiate_request = build_smb_negotiate_request();
            stream
                .write_all(&negotiate_request)
                .await
                .expect("write SMB negotiate");

            // Read NBT + SMB negotiate response
            let mut buf = vec![0u8; 4096];
            let n = time::timeout(Duration::from_secs(3), stream.read(&mut buf))
                .await
                .expect("negotiate response timeout")
                .expect("negotiate response read");

            // NBT header (4 bytes) + SMB header (32 bytes) + negotiate response body
            assert!(n >= 36, "expected at least NBT header + SMB header, got {n}");

            // Verify NBT Session Message type
            assert_eq!(buf[0], 0x00, "NBT TYPE should be Session Message");

            // Verify SMB header signature
            assert_eq!(
                &buf[4..8],
                b"\xffSMB",
                "SMB header should start with \\xffSMB"
            );

            // Verify Command = SMB_COM_NEGOTIATE (0x72)
            assert_eq!(buf[8], 0x72, "SMB Command should be NEGOTIATE (0x72)");

            // Verify Flags has SERVER_TO_REDIR bit set (0x80)
            // Flags is at SMB offset 9 (after Start[4] + Command[1] + Status[4])
            assert!(
                buf[4 + 9] & 0x80 != 0,
                "SMB Flags should have SERVER_TO_REDIR bit (response), got: {:#04x}",
                buf[4 + 9]
            );
        }

        state.stop_all_listeners();
    });
}
