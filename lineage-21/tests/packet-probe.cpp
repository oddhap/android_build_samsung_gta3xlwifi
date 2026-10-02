// SPDX-License-Identifier: Apache-2.0
// Run only in rooted debugging. Every hook is scoped to probe UID/UDP port;
// production firewall chains are never flushed or edited.
#include "Gta3xlwifiLegacyFirewall.h"
#include "NetdConstants.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <grp.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
namespace android::net { std::mutex gBigNetdLock; }
static std::string peer;
static constexpr int UID=99001, PORT=45679;
static bool hookCreated=false;
static int restore(const char* tool, const std::string& commands) {
    int pipefd[2]; if (pipe(pipefd)) return -1;
    const pid_t pid=fork();
    if (!pid) {
        dup2(pipefd[0],STDIN_FILENO); close(pipefd[0]); close(pipefd[1]);
        execl(tool,tool,"--noflush","-w","5",nullptr); _exit(127);
    }
    close(pipefd[0]);
    size_t pos=0;
    while (pos<commands.size()) {
        ssize_t n=write(pipefd[1],commands.data()+pos,commands.size()-pos);
        if (n<=0) break; pos+=n;
    }
    close(pipefd[1]); int code=0; waitpid(pid,&code,0);
    return pos==commands.size() && WIFEXITED(code) && WEXITSTATUS(code)==0 ? 0 : -1;
}
static void replaceAll(std::string& s,const std::string& a,const std::string& b) {
    size_t pos=0; while ((pos=s.find(a,pos))!=std::string::npos) { s.replace(pos,a.size(),b);pos+=b.size(); }
}
int execIptablesRestore(IptablesTarget family, const std::string& input) {
    auto rules=input;
    replaceAll(rules,"gta3xlwifi_","g21p_");
    replaceAll(rules,"fw_","g21p_fw_");
    if (rules.find("-A INPUT -j")!=std::string::npos) {
        // No input hook: owner INPUT rules are still validated by the kernel.
        replaceAll(rules,"*filter\n","*filter\n:g21p_input_anchor -\n");
        replaceAll(rules,"-A INPUT -j","-A g21p_input_anchor -j");
        auto start=rules.find("-A OUTPUT -j");
        auto end=rules.find('\n',start);
        rules.erase(start,end-start+1);
    }
    // This test's hook is restricted to its UID, peer and UDP port. Let only
    // those packets bypass unrelated policies in the running Android 12 ROM.
    if (rules.find(":g21p_OUTPUT -")!=std::string::npos)
        replaceAll(rules,"COMMIT\n","-A g21p_OUTPUT -j ACCEPT\nCOMMIT\n");
    if (family==V4 || family==V4V6)
        if (restore("/system/bin/iptables-restore",rules)) return -1;
    if (family==V6 || family==V4V6)
        if (restore("/system/bin/ip6tables-restore",rules)) return -1;
    return 0;
}
static void require(bool condition,const char* msg) {
    if (!condition) throw std::runtime_error(msg);
}
static void send(const char* message) {
    const pid_t pid=fork(); require(pid>=0,"fork failed");
    if (!pid) {
        gid_t groups[]={3003};
        if (setgroups(1,groups) || setgid(3003) || setuid(UID)) _exit(11);
        int fd=socket(AF_INET,SOCK_DGRAM,0); if (fd<0) _exit(12);
        sockaddr_in addr={}; addr.sin_family=AF_INET; addr.sin_port=htons(PORT);
        inet_pton(AF_INET,peer.c_str(),&addr.sin_addr);
        ssize_t result=sendto(fd,message,strlen(message),0,reinterpret_cast<sockaddr*>(&addr),sizeof(addr));
        int error=errno; close(fd);
        if (result < 0) std::cerr << message << ": send returned " << result << ", errno=" << error << "\n";
        _exit(result>=0 || error==EPERM || error==EACCES ? 0 : 13);
    }
    int code=0; waitpid(pid,&code,0);
    require(WIFEXITED(code) && WEXITSTATUS(code)==0,"probe socket creation/send failed");
}
static unsigned long long drops(const char* chain) {
    const std::string cmd="/system/bin/iptables -w 5 -nvx -L "+std::string(chain);
    FILE* pipe=popen(cmd.c_str(),"r"); require(pipe!=nullptr,"counter query failed");
    char line[512]; unsigned long long packets=0,total=0;
    while (fgets(line,sizeof(line),pipe)) {
        if (strstr(line,"DROP") && sscanf(line,"%llu",&packets)==1) total+=packets;
    }
    require(pclose(pipe)==0,"iptables counter query failed"); return total;
}
static std::string hook(const char* op) {
    return std::string("*filter\n")+op+" OUTPUT -m owner --uid-owner 99001 -p udp -d "+peer+
        " --dport 45679 -j g21p_OUTPUT\nCOMMIT\n";
}
static void cleanup() {
    if (hookCreated) restore("/system/bin/iptables-restore",hook("-D"));
    const char* chains[]={"g21p_input_anchor","g21p_INPUT","g21p_OUTPUT","g21p_iif",
        "g21p_ingress","g21p_lockdown_output","g21p_fw_dozable","g21p_fw_standby",
        "g21p_fw_powersave","g21p_fw_restricted","g21p_fw_low_power_standby",
        "g21p_fw_background","g21p_fw_oem_deny_1","g21p_fw_oem_deny_2","g21p_fw_oem_deny_3"};
    std::string cmd="*filter\n";
    for (const auto* chain:chains) cmd+="-F "+std::string(chain)+"\n";
    for (const auto* chain:chains) cmd+="-X "+std::string(chain)+"\n";
    cmd+="COMMIT\n";
    const int a=restore("/system/bin/iptables-restore",cmd);
    const int b=restore("/system/bin/ip6tables-restore",cmd);
    if (a || b) std::cerr << "Cleanup needs inspection of g21p_ chains.\n";
    else std::cout << "All probe chains and the scoped hook removed.\n";
}
int main(int argc,char** argv) {
    in_addr parsed={};
    if (argc!=2 || getuid()!=0 || inet_pton(AF_INET,argv[1],&parsed)!=1) return 2;
    peer=argv[1];
    using android::net::Gta3xlwifiLegacyFirewall;
    auto& fw=Gta3xlwifiLegacyFirewall::get();
    int result=0;
    try {
        require(fw.setUidRule(1,UID,1)==0,"allowlist installation failed");
        require(restore("/system/bin/iptables-restore",hook("-I"))==0,"scoped hook failed");
        hookCreated=true;
        require(fw.enableChain(1,true)==0,"allowlist enable failed");
        send("gta21-allow"); require(drops("g21p_fw_dozable")==0,"allowlist blocked allowed UID");
        require(fw.setUidRule(1,UID,0)==0,"allowlist removal failed");
        send("gta21-allowlist-blocked"); require(drops("g21p_fw_dozable")==1,"allowlist did not drop test packet");
        require(fw.enableChain(1,false)==0,"allowlist disable failed");
        require(fw.setUidRule(2,UID,2)==0 && fw.enableChain(2,true)==0,"denylist installation failed");
        send("gta21-denylist-blocked"); require(drops("g21p_fw_standby")==1,"denylist did not drop test packet");
        require(fw.setUidRule(2,UID,0)==0,"denylist removal failed");
        send("gta21-clear"); require(drops("g21p_fw_standby")==0,"cleared denylist blocked UID");
        std::cout << "IPv4/IPv6 rule installation and real IPv4 UID allow/deny packet checks passed.\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; result=1; }
    cleanup(); return result;
}
