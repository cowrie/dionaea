// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
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

/// Build a minimal DCERPC bind request for the ATSVC service.
///
/// Uses NDR32 transfer syntax.
fn build_dcerpc_bind_request() -> Vec<u8> {
    // ATSVC UUID: 1ff70682-0a51-30e8-076d-740be8cee98b (little-endian wire format)
    let interface_uuid: [u8; 16] = [
        0x82, 0x06, 0xf7, 0x1f, 0x51, 0x0a, 0xe8, 0x30, 0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce,
        0xe9, 0x8b,
    ];
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
    bind_body.extend_from_slice(&interface_uuid); // Interface UUID
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
    packet.extend_from_slice(&1u32.to_le_bytes()); // CallID
    packet.extend_from_slice(&bind_body);
    packet
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
