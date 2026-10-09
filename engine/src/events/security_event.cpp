#include "intriqo/events/security_event.hpp"
#include <array>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

namespace intriqo::events {
std::string_view severity_name(Severity s) noexcept { switch(s){case Severity::LOW:return "LOW";case Severity::MEDIUM:return "MEDIUM";case Severity::HIGH:return "HIGH";default:return "CRITICAL";} }
std::string_view event_type_name(EventType t) noexcept { switch(t){case EventType::PORT_SCAN:return "PORT_SCAN";case EventType::SYN_FLOOD:return "SYN_FLOOD";case EventType::BRUTE_FORCE:return "BRUTE_FORCE";case EventType::DNS_ANOMALY:return "DNS_ANOMALY";case EventType::UDP_SCAN:return "UDP_SCAN";case EventType::STATISTICAL_ANOMALY:return "STATISTICAL_ANOMALY";default:return "UNKNOWN";} }
namespace {
std::string escape(std::string_view s) { std::string out; for(char c:s){switch(c){case '"':out+="\\\"";break;case '\\':out+="\\\\";break;case '\n':out+="\\n";break;case '\r':out+="\\r";break;case '\t':out+="\\t";break;default:out+=c;}} return out; }
std::string format_timestamp(TimePoint t) { auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()); auto sec=std::chrono::duration_cast<std::chrono::seconds>(ms); auto rem=ms-sec; std::time_t tt=sec.count(); std::tm tm{}; gmtime_r(&tt,&tm); std::ostringstream o; o<<std::put_time(&tm,"%Y-%m-%dT%H:%M:%S")<<'.'<<std::setw(3)<<std::setfill('0')<<rem.count()<<'Z'; return o.str(); }
void value(std::ostringstream& o,const MetadataValue& v){std::visit([&](auto&& x){using T=std::decay_t<decltype(x)>; if constexpr(std::is_same_v<T,std::string>)o<<'"'<<escape(x)<<'"'; else if constexpr(std::is_same_v<T,bool>)o<<(x?"true":"false"); else o<<x;},v);}
std::string uuid(){std::random_device rd; std::mt19937_64 g(rd()); std::array<unsigned char,16> b{}; for(auto& x:b)x=static_cast<unsigned char>(g()); b[6]=(b[6]&0x0f)|0x40; b[8]=(b[8]&0x3f)|0x80; std::ostringstream o; o<<std::hex<<std::setfill('0'); for(int i=0;i<16;i++){o<<std::setw(2)<<int(b[i]); if(i==3||i==5||i==7||i==9)o<<'-';} return o.str();}
}
std::string SecurityEvent::to_json() const { std::ostringstream o; o<<"{\"event_id\":\""<<escape(event_id)<<"\",\"event_type\":\""<<event_type_name(event_type)<<"\",\"severity\":\""<<severity_name(severity)<<"\",\"timestamp\":\""<<format_timestamp(timestamp)<<"\",\"source_address\":\""<<source_address.to_string()<<"\",\"destination_address\":\""<<destination_address.to_string()<<'"'; if(!description.empty())o<<",\"description\":\""<<escape(description)<<'"'; o<<",\"details\":{"; bool first=true; for(const auto& [k,v]:details){if(!first)o<<',';first=false;o<<'"'<<escape(k)<<"\":";value(o,v);} o<<"}}"; return o.str(); }
SecurityEvent make_port_scan_event(const IPv4Address& source,const IPv4Address& destination,Severity sev,std::uint64_t ports,std::uint64_t attempts,double window,std::uint16_t threshold,TimePoint ts){ SecurityEvent e; e.event_id=uuid(); e.timestamp=ts; e.event_type=EventType::PORT_SCAN; e.severity=sev; e.source_address=source; e.destination_address=destination; e.description="Deterministic port scan detected"; e.details.emplace("detector",std::string("port_scan")); e.details.emplace("unique_destination_ports",static_cast<std::int64_t>(ports)); e.details.emplace("connection_attempts",static_cast<std::int64_t>(attempts)); e.details.emplace("window_seconds",window); e.details.emplace("threshold",static_cast<std::int64_t>(threshold)); return e; }
SecurityEvent make_syn_flood_event(
    const IPv4Address& source, const IPv4Address& destination, Severity severity,
    Port destination_port, std::uint64_t attempts, std::uint64_t syn_acks,
    std::uint64_t completed_handshakes, std::uint64_t incomplete_handshakes,
    double incomplete_ratio, double rate_per_second, double window_seconds,
    TimePoint timestamp) {
    SecurityEvent event;
    event.event_id = uuid();
    event.timestamp = timestamp;
    event.event_type = EventType::SYN_FLOOD;
    event.severity = severity;
    event.source_address = source;
    event.destination_address = destination;
    event.description = "Suspicious high-rate incomplete TCP handshakes observed";
    event.details.emplace("detector", std::string("syn_flood"));
    event.details.emplace("destination_port", static_cast<std::int64_t>(destination_port));
    event.details.emplace("initial_syn_attempts", static_cast<std::int64_t>(attempts));
    event.details.emplace("connection_attempts", static_cast<std::int64_t>(attempts));
    event.details.emplace("syn_ack_count", static_cast<std::int64_t>(syn_acks));
    event.details.emplace("completed_handshakes", static_cast<std::int64_t>(completed_handshakes));
    event.details.emplace("incomplete_handshakes", static_cast<std::int64_t>(incomplete_handshakes));
    event.details.emplace("incomplete_ratio", incomplete_ratio);
    event.details.emplace("rate_per_second", rate_per_second);
    event.details.emplace("window_seconds", window_seconds);
    return event;
}
}
