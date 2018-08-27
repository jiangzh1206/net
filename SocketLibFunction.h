#ifndef _SOCKETLIBFUNCTION_H_

#define _SOCKETLIBFUNCTION_H_

#include "SocketLibTypes.h"
#include <string>

namespace net
{
namespace base {
	bool InitSocket();
	void DestroySocket();

	int SocketNodelay(sock fd);
	bool SocketBlock(sock fd);
	bool SocketNonBlock(sock fd);

	int SocketSetSendSize(sock fd, int size);
	int SocketSetRecvSize(sock fd, int size);

	sock Connect(bool isIPV6, const std::string& ip, int port);
	sock Listen(bool isIPV6, const char* ip, int port, int back_num);
	sock Accept(sock listenSocket, struct sockaddr* addr, socklen_t* addr_len);

	sock SocketCreate(int af, int type, int protocol);
	void SocketClose(sock fd);

	std::string GetIPOfSocket(sock fd);
	int SocketSend(sock fd, const char* buffer, int len);

}
};



#endif // !_SOCKETLIBFUNCTION_H_



