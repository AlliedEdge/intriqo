#include "intriqo/transport/event_sink.hpp"
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace intriqo::transport {
FileEventSink::FileEventSink(std::string p):path_(std::move(p)){}
bool FileEventSink::submit(const events::SecurityEvent& e) noexcept { try { std::ofstream out(path_,std::ios::app); if(!out)return false; out<<e.to_json()<<'\n'; return static_cast<bool>(out); } catch(...) { return false; } }
HttpEventSink::HttpEventSink():config_{}{}
HttpEventSink::HttpEventSink(Config c):config_(std::move(c)){}
bool HttpEventSink::submit(const events::SecurityEvent& e) noexcept {
    try {
        std::regex r(R"(^http://([^/:]+)(?::([0-9]+))?(\/.*)$)"); std::smatch m; if(!std::regex_match(config_.url,m,r))return false;
        std::string host=m[1], port=m[2].matched?m[2].str():"80", path=m[3]; addrinfo hints{}; hints.ai_socktype=SOCK_STREAM; addrinfo* res=nullptr; if(getaddrinfo(host.c_str(),port.c_str(),&hints,&res)!=0)return false;
        int fd=-1; for(auto* p=res;p;p=p->ai_next){fd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);if(fd>=0&&connect(fd,p->ai_addr,p->ai_addrlen)==0)break;if(fd>=0){close(fd);fd=-1;}} freeaddrinfo(res); if(fd<0)return false;
        timeval tv{config_.timeout_seconds,0}; setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); auto body=e.to_json(); std::string req="POST "+path+" HTTP/1.1\r\nHost: "+host+"\r\nContent-Type: application/json\r\nContent-Length: "+std::to_string(body.size())+"\r\nConnection: close\r\n"; if(!config_.bearer_token.empty())req+="Authorization: Bearer "+config_.bearer_token+"\r\n"; req+="\r\n"+body; std::size_t sent=0; while(sent<req.size()){auto n=send(fd,req.data()+sent,req.size()-sent,0);if(n<=0){close(fd);return false;}sent+=static_cast<std::size_t>(n);} char buf[128]{}; auto n=recv(fd,buf,sizeof(buf)-1,0); close(fd); if(n<12)return false; return std::string(buf,static_cast<std::size_t>(n)).find(" 2") != std::string::npos;
    } catch(...) { return false; }
}
}
