#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <array>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <condition_variable>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
using namespace std;

// 以太网帧头部
struct EthernetHeader
{
    byte dstMAC[6];			// 目标MAC地址
    byte srcMAC[6];			// 源MAC地址
    WORD ethertype;			// 协议类型
};
// ARP报文
struct ARP 
{
    WORD hardware;			// 硬件类型
    WORD protocol;			// 协议类型
    byte MAC_length;		// MAC地址长度，单位是字节
    byte IPaddress_length;	// 协议长度
    WORD opcode;			// 操作码
    byte srcMAC[6];			// 源MAC地址
    byte srcIP[4];			// 源IP
    byte dstMAC[6];			// 目标MAC地址
    byte dstIP[4];			// 目标IP
};
// IP报文头部
struct IPv4Header
{
    byte ver_ihl;		// 版本类型+头部长度
    byte TOS;			// 服务类型
    WORD Total_len;		// 总长度
    WORD ID;			// 标识
    WORD Flag_fragment; // 标志+片偏移
    byte TTL;			// 生存时间
    byte protocol;		// 协议类型
    WORD checksum;		// 头部校验和
    DWORD srcIP;		// 源IP地址
    DWORD dstIP;		// 目标IP地址
};
// 路由表项
struct RouteEntry 
{
    DWORD network;      // 目的网络
    DWORD netmask;      // 子网掩码
    DWORD nextHop;      // 下一跳
};
// 全局变量
pcap_t* handle;         // 网络设备句柄
byte localMAC[6];       // 网络设备MAC
vector<RouteEntry> routing_table;   // 路由表
vector<DWORD> localIPs;             // 网络设备的IP
unordered_map<DWORD, pair<array<byte, 6>, chrono::steady_clock::time_point>> g_arp_cache;   // arp缓存
const int ARP_CACHE_TIMEOUT_SEC = 300;  // ARP缓存超时时间
mutex g_route_mutex, localIPs_mutex, arp_mutex, g_queue_mutex, g_log_mutex;  // 和锁有关的互斥量
condition_variable g_queue_cv;      // 条件变量用于同步线程
bool running = true;    // 路由器是否在运行
// 用于转发的数据包
struct PacketForForward 
{
    vector<byte> data;
    int length;
};
// 需要转发的数据包列表以及日志列表
queue<PacketForForward> g_pkt_queue;
queue<string> g_log_queue;
// 将DWORD类型的IP地址转为字符串
string ip_to_str(DWORD ip_host) 
{
    struct in_addr a;
    a.s_addr = htonl(ip_host);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return string(buf);
}
// 日志记录
void safe_log(const string& msg) 
{
    lock_guard<mutex> lk(g_log_mutex);
    g_log_queue.push(msg);
}
// 输出日志
void flush_logs() 
{
    lock_guard<mutex> lk(g_log_mutex);
    while (!g_log_queue.empty()) 
    {
        cout << g_log_queue.front();
        g_log_queue.pop();
    }
    cout.flush();
}
// 打印MAC地址
void print_MAC(const byte MAC[6]) 
{
    for (int i = 0; i < 6; i++)
    {
        printf("%02X", MAC[i]);
        if (i < 5) cout << "-";
    }
    cout << endl;
}
// 计算校验和
WORD ip_checksum(const void* vdata, size_t length)
{
    const uint8_t* data = (const uint8_t*)vdata;
    DWORD acc = 0;
    for (size_t i = 0; i + 1 < length; i += 2) 
    {
        WORD word = (data[i] << 8) | data[i + 1];
        acc += word;
    }
    if (length & 1)
        acc += data[length - 1] << 8;
    while (acc >> 16) 
        acc = (acc & 0xFFFF) + (acc >> 16);
    return (WORD)(~acc);
}
// 寻找路由
RouteEntry* find_route(DWORD dst_host)
{
    // 设置线程锁，防止工作线程和捕获线程发生混乱
    lock_guard<mutex> lk(g_route_mutex);
    for (auto& r : routing_table)
        if ((dst_host & r.netmask) == (r.network & r.netmask))
            return &r;
    return nullptr;
}
// 展示路由表
void display_routing_table() 
{
    lock_guard<mutex> lk(g_route_mutex);
    cout << "\n========================================\n";
    cout << "Routing Table:\n";
    cout << "========================================\n";
    cout << "Index  Destination Network    Netmask            Next Hop\n";
    cout << "--------------------------------------------------------\n";
    for (size_t i = 0; i < routing_table.size(); ++i)
    {
        const auto& r = routing_table[i];
        string nextHopStr = (r.nextHop == 0) ? "direct" : ip_to_str(r.nextHop);
        printf("%-5zu  %-20s  %-18s  %s\n", 
               i, 
               ip_to_str(r.network).c_str(),
               ip_to_str(r.netmask).c_str(),
               nextHopStr.c_str());
    }
    cout << "========================================\n\n";
}
// 添加路由
bool add_route(const string& net, const string& mask, const string& nh) 
{
    RouteEntry e;
    e.network = ntohl(inet_addr(net.c_str()));
    e.netmask = ntohl(inet_addr(mask.c_str()));
    e.nextHop = (nh == "0" || nh == "0.0.0.0") ? 0 : ntohl(inet_addr(nh.c_str()));
    // 设置线程锁防止发生混乱
    lock_guard<mutex> lk(g_route_mutex);
    routing_table.push_back(e);
    cout << "Route added: " << net << " / " << mask 
         << " -> " << (e.nextHop == 0 ? "direct" : nh) << "\n";
    return true;
}
// 删除特定的路由表项
bool delete_route_by_index(size_t index) 
{
    lock_guard<mutex> lk(g_route_mutex);
    if (index >= routing_table.size()) 
    {
        cout << "Invalid route index!\n";
        return false;
    }

    routing_table.erase(routing_table.begin() + index);
    return true;
}
// 删除所有路由表项
bool delete_route(const string& net, const string& mask) 
{
    DWORD network = ntohl(inet_addr(net.c_str()));
    DWORD netmask = ntohl(inet_addr(mask.c_str()));
    
    lock_guard<mutex> lk(g_route_mutex);
    for (size_t i = 0; i < routing_table.size(); ++i) 
    {
        if (routing_table[i].network == network && routing_table[i].netmask == netmask) 
        {
            routing_table.erase(routing_table.begin() + i);
            return true;
        }
    }
    return false;
}
// 构造ARP数据包并发送请求
bool send_arp_request(DWORD target_ip_host)
{
    if (!handle) return false;
    byte pkt[42];
    EthernetHeader* eth = (EthernetHeader*)pkt;
    memset(eth->dstMAC, 0xFF, 6);
    memcpy(eth->srcMAC, localMAC, 6);
    eth->ethertype = htons(0x0806);
    ARP* arp = (ARP*)(pkt + sizeof(EthernetHeader));
    arp->hardware = htons(1);
    arp->protocol = htons(0x0800);
    arp->MAC_length = 6;
    arp->IPaddress_length = 4;
    arp->opcode = htons(1);
    memcpy(arp->srcMAC, localMAC, 6);
    arp->srcIP[0] = arp->srcIP[1] = arp->srcIP[2] = arp->srcIP[3] = 0;
    memset(arp->dstMAC, 0, 6);
    DWORD t = htonl(target_ip_host);
    memcpy(arp->dstIP, &t, 4);
    return pcap_sendpacket(handle, pkt, sizeof(pkt)) == 0;
}
// 清理过期的ARP缓存条目
void cleanup_expired_arp_cache()
{
    auto now = chrono::steady_clock::now();
    auto timeout = chrono::seconds(ARP_CACHE_TIMEOUT_SEC);
    for (auto it = g_arp_cache.begin(); it != g_arp_cache.end();)
    {
        if (now - it->second.second > timeout)
            it = g_arp_cache.erase(it);
        else
            ++it;
    }
}
// 将IP地址解析为MAC地址
bool resolve_mac(DWORD ip_host, array<byte, 6>& out_mac, int timeout_ms = 1000)
{
    // 在ARP缓存中寻找是否有当前IP地址的MAC地址
    {
        lock_guard<mutex> lk(arp_mutex);
        cleanup_expired_arp_cache();  // 清理过期条目
        auto it = g_arp_cache.find(ip_host);
        if (it != g_arp_cache.end())
        {
            out_mac = it->second.first;
            return true;
        }
    }
    // 没有则发送ARP请求
    if (!send_arp_request(ip_host)) 
        return false;  // ARP请求发送失败，直接返回
    // 等待ARP响应
    for (int waited = 0; waited < timeout_ms; waited += 50) 
    {
        // 每50ms检查一次缓存，capture_thread线程在后台工作，更新缓存
        this_thread::sleep_for(chrono::milliseconds(50));
        lock_guard<mutex> lk(arp_mutex);
        auto it = g_arp_cache.find(ip_host);
        // 超时则返回false
        if (it != g_arp_cache.end()) 
        {
            out_mac = it->second.first;
            return true;
        }
    }
    return false;
}
// 捕获数据包线程
void capture_thread() 
{
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res;
    // 工作主循环
    while (running) 
    {
        // 捕获数据包
        res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) 
            continue; // timeout
        if (res < 0)
            break;
        // 解析数据包的以太网帧头部
        const EthernetHeader* eth = (const EthernetHeader*)pkt_data;
        WORD etype = ntohs(eth->ethertype);
        // 属于ARP协议
        if (etype == 0x0806) 
        {
            // 解析ARP数据包
            const ARP* arp = (const ARP*)(pkt_data + sizeof(EthernetHeader));
            if (ntohs(arp->opcode) == 2) 
            {
                // 将MAC地址存入ARP缓存
                DWORD sip_host = ntohl(*(DWORD*)arp->srcIP);
                array<byte, 6> mac;
                memcpy(mac.data(), arp->srcMAC, 6);
                lock_guard<mutex> lk(arp_mutex);
                cleanup_expired_arp_cache();  // 添加新条目时清理过期条目
                g_arp_cache[sip_host] = make_pair(mac, chrono::steady_clock::now());
            }
        }
        // 如果是IPv4数据包
        else if (etype == 0x0800)
        {
            if (header->caplen < (int)(sizeof(EthernetHeader) + sizeof(IPv4Header))) continue;
            // 解析IP头部
            const IPv4Header* ip = (const IPv4Header*)(pkt_data + sizeof(EthernetHeader));
            DWORD dst_host = ntohl(ip->dstIP);
            DWORD src_host = ntohl(ip->srcIP);
            // 检查目的MAC是否为已打开设备的MAC地址，不是则跳过，不需要转发
            bool match = true;
            for (int i = 0; i < 6; i++) 
            {
                if (localMAC[i] != eth->dstMAC[i])
                {
                    match = false;
                    break;
                }
            }
            if (!match) continue;
            // 检查目的IP是否为已打开设备的IP地址，如果是则跳过，不需要转发
            {
                lock_guard<mutex> lk(localIPs_mutex);
                bool is_local = false;
                for (DWORD localIP : localIPs)
                {
                    if (dst_host == localIP) 
                    {
                        is_local = true;
                        break;
                    }
                }
                if (is_local) continue;
            }
            // 构造转发数据包
            PacketForForward p;
            p.length = header->caplen;
            p.data.resize(p.length);
            memcpy(p.data.data(), pkt_data, p.length);
            // 放入待转发队列并通知worker线程
            {
                lock_guard<mutex> lk(g_queue_mutex);
                g_pkt_queue.push(move(p));
            }
            g_queue_cv.notify_one();
        }
    }
}
// 转发数据包线程
void worker_thread() 
{
    // 工作主循环
    while (running) 
    {
        PacketForForward p;
        // 等待队列中的数据包
        {
            unique_lock<mutex> lk(g_queue_mutex);
            g_queue_cv.wait(lk, [] { return !g_pkt_queue.empty() || !running; });
            if (!running && g_pkt_queue.empty()) break;
            p = move(g_pkt_queue.front());
            g_pkt_queue.pop();
        }
        if (p.length < (int)(sizeof(EthernetHeader) + sizeof(IPv4Header))) continue;
        // 解析数据包头部
        EthernetHeader* eth = (EthernetHeader*)p.data.data();
        IPv4Header* ip = (IPv4Header*)(p.data.data() + sizeof(EthernetHeader));
        DWORD dst_host = ntohl(ip->dstIP);
        DWORD src_host = ntohl(ip->srcIP);
        // 寻找路由
        RouteEntry* route = find_route(dst_host);
        // 找不到路由信息，输出错误
        if (!route) 
        {
            stringstream ss;
            ss << "[DROP] No route found for " << ip_to_str(dst_host) << "\n";
            safe_log(ss.str());
            continue;
        }
        // 确定下一跳IP地址（直接连接则用目标IP，否则用路由表中的下一跳）
        DWORD nextHopHost = (route->nextHop == 0) ? dst_host : route->nextHop;
        array<byte, 6> nexthostmac;
        // 解析下一跳的MAC地址
        if (!resolve_mac(nextHopHost, nexthostmac, 1000)) 
        {
            stringstream ss;
            ss << "[DROP] Failed to resolve MAC for next hop " << ip_to_str(nextHopHost) << "\n";
            safe_log(ss.str());
            continue;
        }
        
        // 修改数据包头部
        vector<byte> outbuf = move(p.data);
        EthernetHeader* oeth = (EthernetHeader*)outbuf.data();
        memcpy(oeth->srcMAC, localMAC, 6);            // 源MAC改为路由器MAC
        memcpy(oeth->dstMAC, nexthostmac.data(), 6);  // 目的MAC改为下一跳MAC

        // 检查并更新TTL
        byte original_ttl = ip->TTL;
        if (ip->TTL <= 1)
        {
            stringstream ss;
            ss << "[DROP] TTL expired for packet " << ip_to_str(src_host) 
               << " -> " << ip_to_str(dst_host) << " (TTL=" << (int)ip->TTL << ")\n";
            safe_log(ss.str());
            continue;
        }
        // TTL减1
        ip->TTL--;  
        // 重新计算IP头部校验和
        ip->checksum = 0;
        size_t ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
        ip->checksum = htons(ip_checksum((const void*)ip, ip_hdr_len));

        // 发送数据包
        int r = pcap_sendpacket(handle, outbuf.data(), (int)outbuf.size());
        if (r != 0) 
        {
            stringstream ss;
            ss << "[SEND ERROR] pcap_sendpacket failed for " << ip_to_str(src_host) 
               << " -> " << ip_to_str(dst_host) << "\n";
            safe_log(ss.str());
        } 
        else 
        {
            string nextHopStr = (route->nextHop == 0) ? "direct" : ip_to_str(nextHopHost);
            stringstream ss;
            ss << "[FORWARD] " << ip_to_str(src_host) << " -> " << ip_to_str(dst_host) 
               << " via " << nextHopStr << " (TTL: " << (int)original_ttl << " -> " << (int)ip->TTL << ")\n";
            safe_log(ss.str());
        }
    }
}
// 让用户选择需要打开的网卡设备
static pcap_if_t* select_device(pcap_if_t* alldevices, int count)
{
    pcap_if_t* d;				// 遍历指针
    int op;						// 设备编号
    cout << "Please enter the number of the Network interface Device you want to open:";
    cin >> op;

LOOP:
    if (op < 1 || op > count)			// 输入的数字无效
    {
        cout << "Invalid number!Out of range!" << endl;
        cout << "continue or quit ([c/q]):";// 选择继续或者退出
        char op;
        cin >> op;
        if (op == 'c' || op == 'C')
            goto LOOP;
        else
        {
            pcap_freealldevs(alldevices);	// 释放设备列表
            exit(0);
        }
    }
    // 寻找指定的设备
    int i;
    for (d = alldevices, i = 0;i < op - 1 && d != nullptr;d = d->next, i++);

    return d;
}
// 获取打开的网卡设备的MAC
static void Get_local_MAC(const string device_name, byte mac[6])
{
    IP_ADAPTER_INFO adapterinfo[16];		// 最多16个适配器
    DWORD dwBufLen = sizeof(adapterinfo);	// 缓冲区大小
    // 调用系统API获取网络适配器信息
    DWORD dwStatus = GetAdaptersInfo(adapterinfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS)
    {
        std::cerr << "GetAdaptersInfo failed!" << std::endl;
        return;
    }
    // 提取设备名称中的GUID，也就是大括号包裹的部分
    string guid;
    size_t pos = device_name.find("{");
    if (pos != string::npos)
        guid = device_name.substr(pos);
    // 根据GUID匹配并找到MAC地址
    for (PIP_ADAPTER_INFO p = adapterinfo;p != nullptr;p = p->Next)
    {
        if (guid.find(p->AdapterName) != string::npos)
        {
            memcpy(mac, p->Address, 6);
            return;
        }
    }
}
int main() 
{
    pcap_if_t* alldevs;			// 设备列表的存储链表
    pcap_if_t* device;				// 遍历指针
    char errbuf[PCAP_ERRBUF_SIZE];	// 存储错误信息，256字节
    cout << "=================================Devices List=================================" << endl;
    // 从本地设备中获取可用设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) 
    {
        // 查找失败，则输出错误信息
        cerr << "pcap_findalldevs_ex failed: " << errbuf << "\n";
        return -1;
    }
    // 显示当前存在的设备信息
    int idx = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next, idx++)
        cout << (idx+1) << ". " << (d->name ? d->name : "") << " - " << (d->description ? d->description : "") << "\n";
    cout << "Total devices:" << idx << endl;
    cout << endl;
    // 选择要打开的设备
    device = select_device(alldevs, idx);
    if (!device) 
        return -1; 
    // 打开设备
    handle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
    if (!handle)
    {
        cerr << "pcap_open failed: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return -1;
    }
    cout << "Successfully open network device:" << (device->description ? device->description : device->name) << "\n";
    // 获取设备MAC地址
    Get_local_MAC(device->name, localMAC);
    cout << "Local MAC: ";
    print_MAC(localMAC);
    // 获取网络设备IP
    {
        lock_guard<mutex> lk(localIPs_mutex);
        for (pcap_addr_t* a = device->addresses; a; a = a->next)
        {
            if (a->addr && a->addr->sa_family == AF_INET)
            {
                DWORD ip_host = ntohl(((sockaddr_in*)a->addr)->sin_addr.s_addr);
                localIPs.push_back(ip_host);
                cout << "Local IP: " << ip_to_str(ip_host) << "\n";
            }
        }
    }
    // 路由器开始工作
    cout << "\n=== Router Initialization ===\n";
    cout << "Type 'help' for commands.\n\n";
    thread capt(capture_thread);
    thread worker(worker_thread);
    cout << "Router running. Type 'help' for commands.\n";
    string line;
    cin.ignore();  // 清除之前cin>>留下的换行符
    while (running) 
    {
        cout << "router> ";
        cout.flush();
        getline(cin, line);
        
        if (line.empty()) continue;
        
        stringstream ss(line);
        string cmd;
        ss >> cmd;
        // 根据命令进入不同分支，help显示当前可用命令，add添加路由表项，del删除全部路由表项
        // deli删除指定路由表项，show显示路由表，log显示当前日志，quit/exit退出并停止路由器
        if (cmd == "help" || cmd == "h") 
        {
            cout << "\nAvailable commands:\n";
            cout << "  add <network> <netmask> <next_hop>  - Add a route (use 0 or 0.0.0.0 for direct)\n";
            cout << "  del <network> <netmask>             - Delete a route by network and mask\n";
            cout << "  deli <index>                        - Delete a route by index (see 'show')\n";
            cout << "  show                                - Display routing table\n";
            cout << "  log                                 - Display pending logs\n";
            cout << "  quit / exit                         - Stop router and exit\n";
            cout << "  help                                - Show this help message\n\n";
        }
        // 添加路由项
        else if (cmd == "add" || cmd == "a") 
        {
            string net, mask, nh;
            if (ss >> net >> mask >> nh) 
                add_route(net, mask, nh);
            else 
                cout << "Usage: add <network> <netmask> <next_hop>\n";
        }
        // 删除全部路由表项
        else if (cmd == "del" || cmd == "d")
        {
            string net, mask;
            if (ss >> net >> mask) 
                delete_route(net, mask);
            else 
                cout << "Usage: del <network> <netmask>\n";
        }
        // 删除指定路由表项
        else if (cmd == "deli") 
        {
            size_t index;
            if (ss >> index) 
                delete_route_by_index(index);
            else 
                cout << "Usage: deli <index>\n";
        }
        // 显示路由表
        else if (cmd == "show" || cmd == "s") 
            display_routing_table();
        // 显示日志记录
        else if (cmd == "log" || cmd == "logs" || cmd == "l") 
            flush_logs();
        // 退出
        else if (cmd == "quit" || cmd == "exit" || cmd == "q") 
        {
            cout << "Stopping router...\n";
            running = false;
            g_queue_cv.notify_all();
            break;
        }
        else 
            cout << "Unknown command: " << cmd << ". Type 'help' for available commands.\n";
    }
    // 结束运行，释放设备并清理资源
    pcap_breakloop(handle);
    capt.join();
    worker.join();
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    cout << "Stopped.\n";
    return 0;
}
