#include "Socket.h"
#include "SocketLibFunction.h"

namespace net {


TcpSocket::TcpSocket(sock fd, bool serverSide)
	: mFD(fd)
	, mServerSide(serverSide)
{
}

TcpSocket::~TcpSocket()
{
	net::base::SocketClose(mFD);
}

sock TcpSocket::getFD() const
{
	return mFD;
}

TcpSocket::PTR TcpSocket::Create(sock fd, bool serverSide)
{
	// 私有构造,调用unique/shared_ptr
	struct make_unique_enable_s : public TcpSocket
	{
	public:
		make_unique_enable_s(sock fd, bool serverSide)
			: TcpSocket(fd, serverSide)
		{
		}
	};
	
	return PTR(new make_unique_enable_s(fd, serverSide));
}

void TcpSocket::SocketNodelay() const
{
	base::SocketNodelay(mFD);
}

bool TcpSocket::SocketNonblock() const
{
	return base::SocketNonBlock(mFD);
}

void TcpSocket::SetSendSize(int sdSize) const
{
	base::SocketSetSendSize(mFD, sdSize);
}

void TcpSocket::SetRecvSize(int rdSize) const
{
	base::SocketSetRecvSize(mFD, rdSize);
}

std::string TcpSocket::GetIP() const
{
	return base::GetIPOfSocket(mFD);
}

bool TcpSocket::isServerSide() const
{
	return mServerSide;
}

//-------------------------------------------------------------------------------------------------

ListenSocket::PTR ListenSocket::Create(sock fd)
{
	// 私有构造,调用unique/shared_ptr
	struct make_unique_enable_s : public ListenSocket
	{
	public:
		make_unique_enable_s(sock fd) : ListenSocket(fd) {}
	};

	return PTR(new make_unique_enable_s(fd));
}

TcpSocket::PTR ListenSocket::Accept()
{
	sock clientFD = base::Accept(mFD, nullptr, nullptr);
	if (INVALID_SOCKET == clientFD) {
		if (EINTR == sErrno) {
			throw EintrError();
		} else {
			throw AcceptError(sErrno);
		}
	}

	return TcpSocket::Create(clientFD, true);
}

ListenSocket::ListenSocket(sock fd)
	: mFD(fd)
{
}

ListenSocket::~ListenSocket()
{
	base::SocketClose(mFD);
}

}


