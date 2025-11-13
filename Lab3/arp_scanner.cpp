#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
using namespace std;

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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

// 打印MAC地址
void print_MAC(const byte MAC[6])
{
	for (int i = 0;i < 6;i++)
	{
		printf("%02X", MAC[i]);
		if (i < 5) cout << "-";
	}
	cout << endl;
}

// 打印设备信息
int PrintDeviceInfo(pcap_if_t* device_list)
{
	pcap_if_t* d;           // 遍历指针
	int count = 0;			// 可用设备数量
	for (d = device_list;d != nullptr;d = d->next)				// 开始遍历
	{
		cout << (count + 1) << ".Device:" << d->name << endl;		// 设备序号
		if (d->description)
			cout << "Description:" << d->description << endl;	// 设备描述
		else
			cout << "No description available" << endl;
		// 打印IP地址和子网掩码
		for (pcap_addr_t* a = d->addresses;a != nullptr;a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				char ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, ip, INET_ADDRSTRLEN);
				cout << "IP address: " << ip << endl;
			}
			if (a->netmask)
			{
				char mask[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &((struct sockaddr_in*)a->netmask)->sin_addr, mask, INET_ADDRSTRLEN);
				cout << "Netmask: " << mask << endl;
			}
		}
		count++;
	}
	cout << "Total devices:" << count << endl;
	return count;
}

// 让用户选择需要打开的网卡设备
pcap_if_t* select_device(pcap_if_t* alldevices, int count)
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
void GetLocalIPandMAC(const string device_name, byte mac[6])
{
	IP_ADAPTER_INFO adapterinfo[16];		// 最多16个适配器
	DWORD dwBufLen = sizeof(adapterinfo);	// 缓冲区大小
	// 调用系统API获取网络适配器信息
	DWORD dwStatus = GetAdaptersInfo(adapterinfo, &dwBufLen);
	if (dwStatus != ERROR_SUCCESS) {
		std::cerr << "GetAdaptersInfo failed!" << std::endl;
		return;
	}
	// 提取设备名称中的GUID，也就是大括号包裹的部分
	string guid;
	size_t pos = device_name.find("{");
	if (pos != string::npos) {
		guid = device_name.substr(pos);
	}
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
	pcap_if_t* alldevices;			// 设备列表的存储链表
	pcap_if_t* device;				// 遍历指针
	char errbuf[PCAP_ERRBUF_SIZE];	// 存储错误信息，256字节
	byte localIP[4];				// 需要打开设备的IP
	byte targetIP[4];				// 目标IP
	byte localMAC[6];				// 本机MAC地址
	byte packet[42];				// 数据包
	int count;						// 可用设备数量

	cout << "=================================Devices List=================================" << endl;

	// 从本地设备中获取可用设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevices, errbuf) == -1)
	{
		// 查找失败，则输出错误信息
		cerr << "ERROR:" << errbuf << endl;
		return 1;
	}
	// 查找成功的话，设备列表已经存储在alldevices里面
	count = PrintDeviceInfo(alldevices);
	device = select_device(alldevices, count);
	if (!device)
		return 1;
	pcap_t* handle;
	// 打开设备
	handle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
	if (!handle)
	{
		cerr << "ERROR:" << errbuf << endl;
		return 1;
	}
	cout << "Successfully open network device:" << device->name << endl;
	
	// 输入目标地址的IP
	string targetip;
	cout << "Please enter the target IP address:";
	cin >> targetip;
	inet_pton(AF_INET, targetip.c_str(), targetIP);

	// 获取该设备的IP以及MAC
	struct sockaddr_in* sin = (struct sockaddr_in*)device->addresses->addr;
	DWORD ip = sin->sin_addr.S_un.S_addr; // 网络字节序，转换IP的格式
	memcpy(localIP, &ip, 4);
	GetLocalIPandMAC(device->name, localMAC);
	cout << "Source IP and MAC: " << inet_ntoa(sin->sin_addr) << " -> ";
	print_MAC(localMAC);

	// 构造ARP报文
	EthernetHeader* eth = (EthernetHeader*)packet;
	ARP* arp = (ARP*)(packet + sizeof(EthernetHeader));
	// 以太网帧头部
	memset(eth->dstMAC, 0xFF, 6);	// 广播所有设备
	memcpy(eth->srcMAC, localMAC, 6);
	eth->ethertype = htons(0x0806);	// ARP协议
	// ARP报文
	arp->hardware = htons(0x0001);	// 硬件类型为以太网
	arp->protocol = htons(0x0800);	
	arp->MAC_length = 6;
	arp->IPaddress_length = 4;
	arp->opcode = htons(0x0001);
	memcpy(arp->srcIP, localIP, 4);
	memcpy(arp->dstIP, targetIP, 4);
	memcpy(arp->srcMAC, localMAC, 6);
	memset(arp->dstMAC, 0, 6);
	
	// pcap_sendpacket()函数能够利用网卡设备的句柄发送数据包
	if (pcap_sendpacket(handle, packet, 42) != 0)
	{
		cerr << "Error sending ARP request." << endl;
		return -1;
	}
	// 捕获ARP数据包
	struct pcap_pkthdr* header;
	const u_char* recv_data;
	int res;
	while ((res = pcap_next_ex(handle, &header, &recv_data)) >= 0) 
	{
		if (res == 0) continue;
		// 解析以太网帧
		EthernetHeader* recv_eth = (EthernetHeader*)recv_data;
		if (ntohs(recv_eth->ethertype) == 0x0806) 
		{
			// 解析ARP数据包
			ARP* recv_arp = (ARP*)(recv_data + sizeof(EthernetHeader));
			if (ntohs(recv_arp->opcode) == 2) 
			{
				// 验证IP，返回的数据包中的IP是否和目标IP一致
				if (memcmp(recv_arp->srcIP, targetIP, 4) == 0)
				{
					cout << "Target IP and MAC: " << targetip << " -> ";
					print_MAC(recv_arp->srcMAC);
					break;
				}
			}
		}
	}

	pcap_close(handle);
	pcap_freealldevs(alldevices);
	
	return 0;
}

