#include "SocketLibFunction.h"


namespace net {
namespace base {
	

bool InitSocket()
{
	bool ret = true;
#if defined PLATFORM_WINDOWS
	static WSADATA g_WSAData;
	static bool WinSockIsInit = false;
	if (WinSockIsInit) {
		return true;
	}
	if (WSAStartup(MAKEWORD(2, 2), &g_WSAData) == 0) {
		WinSockIsInit = true;
	} else {
		ret = false;
	}
#else
	signal(SIGPIPE, SIG_IGN);
#endif
	return ret;
}

void DestroySocket()
{
#if defined PLATFORM_WINDOWS
	WSACleanup();
#endif
}

int SocketNodelay(sock fd)
{
	// TCP_NODELAY ����Nagle�㷨(����ֻ����д�������ۻ���һ����֮�󣬲Żᱻ���ͳ�ȥ),������ʱ(��������д40ms�ӳ�)
	const int flag = 1;
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
}

bool SocketBlock(sock fd)
{
	int err;
	unsigned long ul = false;	// ����
#if defined PLATFORM_WINDOWS
	err = ioctlsocket(fd, FIONBIO, &ul);
#else 
	err = ioctl(fd, FIONBIO, &ul);
#endif	
	
	return err != SOCKET_ERROR;
}

bool SocketNonBlock(sock fd)
{
	int err;
	unsigned long ul = true;	// ������
#if defined PLATFORM_WINDOWS
	err = ioctlsocket(fd, FIONBIO, &ul);
#else
	err = ioctl(fd, FIONBIO, &ul);
#endif

	return err != SOCKET_ERROR;
}

int SocketSetSendSize(sock fd, int size)
{
	// ͨ��socket
	return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&size, sizeof(size));
}

int SocketSetRecvSize(sock fd, int size)
{
	return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&size, sizeof(size));
}

// TODO::Connect�Ƿ�ֱ�ӷ���TcpSocket::PTR
sock Connect(bool isIPV6, const std::string & ip, int port)
{
	InitSocket();

	struct sockaddr_in ip4Addr = {0};
	struct sockaddr_in6 ip6Addr = {0};
	struct sockaddr_in* paddr = &ip4Addr;
	int addrLen = sizeof(ip4Addr);

	// һ��Э��, protocol = 0
	sock clientFd = isIPV6 ? SocketCreate(AF_INET6, SOCK_STREAM, 0) : SocketCreate(AF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == clientFd) {
			return clientFd;
	}

	bool ptonRet = false;		// ��ַת��,���10���Ƶ�2����
	if (isIPV6) {
		memset(&ip6Addr, 0, sizeof(ip6Addr));
		ip6Addr.sin6_family = AF_INET6;
		ip6Addr.sin6_port = htons(port);
		ptonRet = inet_pton(AF_INET6, ip.c_str(), &ip6Addr.sin6_addr) > 0;
		paddr = (struct sockaddr_in*)&ip6Addr;
		addrLen = sizeof(ip6Addr);
	} else {
		ip4Addr.sin_family = AF_INET;
		ip4Addr.sin_port = htons(port);
		ptonRet = inet_pton(AF_INET, ip.c_str(), &ip4Addr.sin_addr) > 0;
	}

	if (!ptonRet) {
		SocketClose(clientFd);
		return INVALID_SOCKET;
	}

	while (connect(clientFd, (struct sockaddr*)paddr, addrLen) < 0) {
		if (EINTR == sErrno) {		// ϵͳ�����ж�
			continue;
		}
		SocketClose(clientFd);
		return INVALID_SOCKET;
	}

	return clientFd;
}

// server
sock Listen(bool isIPV6, const char * ip, int port, int back_num)
{
	InitSocket();

	struct sockaddr_in ip4Addr = {0};
	struct sockaddr_in6 ip6Addr = {0};
	struct sockaddr_in* paddr = &ip4Addr;
	int addrLen = sizeof(ip4Addr);

	// һ��Э��, protocol = 0
	sock socketfd = isIPV6 ? SocketCreate(AF_INET6, SOCK_STREAM, 0) : SocketCreate(AF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == socketfd) {
		return socketfd;
	}

	bool ptonRet = false;		// ��ַת��,���10���Ƶ�2����
	if (isIPV6) {
		memset(&ip6Addr, 0, sizeof(ip6Addr));
		ip6Addr.sin6_family = AF_INET6;
		ip6Addr.sin6_port = htons(port);
		ptonRet = inet_pton(AF_INET6, ip, &ip6Addr.sin6_addr) > 0;
		paddr = (struct sockaddr_in*)&ip6Addr;
		addrLen = sizeof(ip6Addr);
	} else {
		ip4Addr.sin_family = AF_INET;
		ip4Addr.sin_port = htons(port);
		ptonRet = inet_pton(AF_INET, ip, &ip4Addr.sin_addr) > 0;
	}

	const int reuseValue = 1;
	if (!ptonRet || setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuseValue, sizeof(int)) < 0) {
		SocketClose(socketfd);
		return INVALID_SOCKET;
	}

	const int bindRet = bind(socketfd, (struct sockaddr*)paddr, addrLen);
	if (bindRet == SOCKET_ERROR || listen(socketfd, back_num) == SOCKET_ERROR) {
		SocketClose(socketfd);
		return INVALID_SOCKET;
	}

	return socketfd;
}

sock Accept(sock listenSocket, sockaddr * addr, socklen_t * addrLen)
{
	return accept(listenSocket, addr, addrLen);
}

sock SocketCreate(int af, int type, int protocol)
{
	return socket(af, type, protocol);
}

void SocketClose(sock fd)
{
#if defined PLATFORM_WINDOWS
	closesocket(fd);
#else
	close(fd);
#endif
}

static std::string get_ip_str(const struct sockaddr* sa)
{
	char ipstr[INET6_ADDRSTRLEN] = {0};
	switch (sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), ipstr, sizeof(ipstr));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in*)sa)->sin_addr), ipstr, sizeof(ipstr));
		break;
	default:
		return "Unknow AF";
	}

	return ipstr;
}

std::string GetIPOfSocket(sock fd)
{
#if defined PLATFORM_WINDOWS
	struct sockaddr name = {0};
	int nameLen = sizeof(name);

	// ��ȡ�Զ˵�ַ
	if (getpeername(fd, (struct sockaddr*)&name, &nameLen) == 0) {
		return get_ip_str(&name);
	}
#else
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	if (getpeername(fd, (struct sockaddr*)&name, &namelen) == 0) {
		return get_ip_str((const struct sockaddr*)&name);
	}
#endif

	return std::string();
}

int SocketSend(sock fd, const char * buffer, int len)
{
	// ��������ڷ�����ģʽ�µ����������������ڸò���û����ɾͷ����������,�������²��Ǵ���
	// EINTR(�ж�) ��EWOULDBLOCK ��EAGAIN
	int transform = send(fd, buffer, len, 0);		// ��write����(MSG_DONTROUTE,MSG_DONTWAIT)
	if (transform < 0 && S_EWOULDBLOCK == sErrno) {
		transform = 0;
	}

	// transform < 0 is error
	return transform;
}

}
}
