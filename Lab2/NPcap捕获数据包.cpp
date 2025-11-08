#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include "pcap.h"
#include <string>
#include <ws2tcpip.h>
#include <iomanip>
#include <sstream>
using namespace std;

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// 以太网帧头部
struct EthernetHeader
{
	byte dstMAC[6];		// 目标MAC地址
	byte srcMAC[6];		// 源MAC地址
	WORD ethertype;		// 协议类型
};

// IP报文头部
struct IPHeader
{
	byte ver_ihl;		// 版本类型+头部长度
	byte TOS;			// 服务类型
	WORD Total_len;		// 总长度
	WORD ID;			// 标识
	WORD Flag_fragment; // 标志+片偏移
	byte TTL;			// 生存时间
	byte protocol;		// 协议类型
	WORD Check_sum;		// 头部校验和
	in_addr srcIP;		// 源IP地址
	in_addr dstIP;		// 目标IP地址
};

// MAC地址转字符串
string MACtostring(const byte* MAC)
{
	stringstream ss;					// 创建一个字符串流对象
	ss << hex << setfill('0');			// 设置流格式为输出16进制
	for (int i = 0; i < 6; i++)			// 循环处理每个字节
	{
		ss << setw(2) << (int)MAC[i];
		if (i < 5) ss << ":";			// 只需要5个分隔符
	}
	return ss.str();
}

// 计算头部校验和，将IP头部除校验和之外全部划分为多个16位的部分并累加，之后取反得到校验和
WORD calculate_check_num(const IPHeader* header)
{
	DWORD sum = 0;									// 设置校验和为0
	WORD* ptr = (WORD*)header;						// 将header指针转成16位的
	sum += ((int)header->ver_ihl << 8) | (int)header->TOS;	// 前8位和后8位通过或运算拼接成16位，版本+头部长度+服务类型
	sum += ntohs(header->Total_len);				// 16位的总长度，使用ntohs将网络序转换成主机序
	sum += ntohs(header->ID);						// 16位的标识
	sum += ntohs(header->Flag_fragment);			// 16位的标志+片偏移
	sum += ((int)header->TTL << 8) | (int)header->protocol;	// 将8位的生存时间和8位的协议类型拼接
	sum += ntohs(header->srcIP.S_un.S_un_w.s_w1);	// 源IP前两个字节
	sum += ntohs(header->srcIP.S_un.S_un_w.s_w2);	// 源IP后两个字节
	sum += ntohs(header->dstIP.S_un.S_un_w.s_w1);	// 目标IP前两个字节
	sum += ntohs(header->dstIP.S_un.S_un_w.s_w2);	// 目标IP后两个字节
	while ((sum >> 16)!=0)						// 若发生进位，则将进位部分与低16位累加，直至没有进位
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}
	sum = ~sum;										// 取反得到校验码
	return sum;
}

// 打印设备信息
int PrintDeviceInfo(pcap_if_t* device_list)
{
	pcap_if_t* d;           // 遍历指针
	int count = 0;			// 可用设备数量
	for (d = device_list;d != nullptr;d = d->next)				// 开始遍历
	{
		cout << (count+1) << ".Device:" << d->name << endl;		// 设备序号
		if (d->description)
			cout << "Description:" << d->description << endl;	// 设备描述
		else
			cout << "No description available" << endl;
		count++;
	}
	cout << "Total devices:" << count << endl;
	return count;
}

// 让用户选择需要打开的网卡设备
pcap_if_t* select_device(pcap_if_t* alldevices)
{
	int count;		// 可用设备数量
	pcap_if_t* d;	// 遍历指针
	count = PrintDeviceInfo(alldevices);	// 调用函数打印设备信息并返回设备总数

LOOP: 
	// 用户选择要打开的网卡设备
	int choice;
	cout << "Enter the number of the Network interface Device you want to open:";
	cin >> choice;
	if (choice<1 || choice>count)			// 输入的数字无效
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
	for (d = alldevices, i = 0;i < choice - 1 && d != nullptr;d = d->next, i++);
	
	return d;
}

// 处理数据包
void PackageHandler(const pcap_pkthdr* header, const u_char* packet)
{
	// 数据包过小，无法解析
	if (header->caplen < sizeof(EthernetHeader) + sizeof(IPHeader)) 
	{
		cout << "The length of the data packet is too short, parsing failed!" << endl;
		return;
	}
	// 解析以太网帧头部
	const EthernetHeader* ethheader = (const EthernetHeader*)packet;

	cout << "source MAC address:" << MACtostring(ethheader->srcMAC) << endl;
	cout << "destination MAC address:" << MACtostring(ethheader->dstMAC) << endl;

	// 解析IP数据包头部，以太网帧占14字节
	const IPHeader* IPheader = (const IPHeader*)(packet + 14);
	cout << "source IP address:" << inet_ntoa(IPheader->srcIP) << endl;
	cout << "destination IP address:" << inet_ntoa(IPheader->dstIP) << endl;
	if (ntohs(IPheader->Check_sum) == 0)
		cout << "original checksum:0 (checksum offloading)" << endl;
	else
		cout << "original checksum:" << ntohs(IPheader->Check_sum) << endl;
	cout << "calculated checksum:" << calculate_check_num(IPheader) << endl;
}

// 捕获数据包
void CaptureDataPackage(pcap_t* handle)
{
	pcap_pkthdr* header;    // 数据包头
	const u_char* packet;   // 数据包本身
	int result;
	cout << "Start capturing data packets ..." << endl;
	int packetnum = 0;
	while(true)				// 无限循环捕获
	{
		result = pcap_next_ex(handle, &header, &packet);
		// 超时，继续等待
		if (result == 0) 
		{
			continue;
		}
		packetnum++;
		cout << "the number of data packet: " << packetnum << endl;
		cout << "the length is:" << header->len << "bytes" << endl;
		cout << "Start analysis ..." << endl;
		PackageHandler(header, packet);	// 对数据包进行分析
		if (packetnum == 20)			// 当捕获20个数据包时停止
			break;
	}
	pcap_close(handle);					// 关闭句柄并释放相关资源
}

int main()
{
	pcap_if_t* alldevices;			// 设备列表的存储链表
	char errbuf[PCAP_ERRBUF_SIZE];	// 存储错误信息，256字节

	cout << "=================================Devices List=================================" << endl;

	// 从本地设备中获取可用设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevices, errbuf) == -1)
	{
		// 查找失败，则输出错误信息
		cerr << "ERROR:" << errbuf << endl;
		return 1;
	}
	// 查找成功的话，设备列表已经存储在alldevices里面
	pcap_if_t* device = select_device(alldevices);
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
	cout<<"Successfully open network device:"<< device->name << endl;
	pcap_freealldevs(alldevices);
	CaptureDataPackage(handle);

	return 0;
}
