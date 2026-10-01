/// Engine library stub.
///
/// This translation unit exists solely to satisfy the linker requirement that
/// a static library must contain at least one object file.  It will be
/// replaced by real subsystem implementations as the engine is built out.
///
/// Subsystems to implement (in dependency order):
///   1. common/types.cpp       — IPv4Address::to_string, protocol_name
///   2. packet/parser.cpp      — Ethernet/IP/TCP/UDP header parsing
///   3. flow/flow_table.cpp    — Flow construction, lifecycle, expiry
///   4. features/extractor.cpp — FlowFeatures::from_flow
///   5. events/security_event.cpp — SecurityEvent::to_json
///   6. detection/port_scan_detector.cpp
///   7. pipeline/pipeline_impl.cpp
///   8. capture/pcap_source.cpp  (requires libpcap)
///   9. runtime/engine_impl.cpp

namespace intriqo {
// Intentionally empty — stub translation unit.
} // namespace intriqo
