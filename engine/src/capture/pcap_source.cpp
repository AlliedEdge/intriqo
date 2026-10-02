#include "intriqo/capture/capture.hpp"
#include <fstream>
#include <thread>
#include <vector>

namespace intriqo::capture {
namespace { std::uint32_t read32(const unsigned char* p,bool swap){std::uint32_t x=std::uint32_t(p[0])|std::uint32_t(p[1])<<8|std::uint32_t(p[2])<<16|std::uint32_t(p[3])<<24; if(!swap)return x; return (x>>24)|((x>>8)&0xff00)|((x<<8)&0xff0000)|(x<<24);} }
PcapReplaySource::PcapReplaySource(PcapReplayConfig c):config_(std::move(c)){}
void PcapReplaySource::set_callback(PacketCallback cb){callback_=std::move(cb);}
void PcapReplaySource::stop() noexcept{stopped_=true;}
std::string PcapReplaySource::description() const{return "pcap:"+config_.file_path;}
void PcapReplaySource::start(){std::ifstream in(config_.file_path,std::ios::binary); if(!in||!callback_)return; unsigned char hdr[24]{};in.read(reinterpret_cast<char*>(hdr),24);if(in.gcount()!=24)return; const std::uint32_t magic=read32(hdr,false);bool swap=false; if(magic==0xd4c3b2a1||magic==0x4d3cb2a1)swap=true; if(magic!=0xa1b2c3d4&&magic!=0xd4c3b2a1&&magic!=0xa1b23c4d&&magic!=0x4d3cb2a1)return; stopped_=false; while(!stopped_){unsigned char ph[16]{};in.read(reinterpret_cast<char*>(ph),16);if(in.gcount()!=16)break;auto sec=read32(ph,swap), usec=read32(ph+4,swap), incl=read32(ph+8,swap);if(incl>16*1024*1024)break;std::vector<std::byte> bytes(incl);in.read(reinterpret_cast<char*>(bytes.data()),incl);if(static_cast<std::size_t>(in.gcount())!=incl)break; TimePoint ts=TimePoint{std::chrono::seconds(sec)+std::chrono::microseconds(usec)}; callback_({ts,std::span<const std::byte>(bytes),read32(hdr+20,swap)}); }}
}
