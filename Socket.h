#ifndef _SOCKET_H_
#define _SOCKET_H_

#include "NonCopyable.h"
#include "SocketLibTypes.h"

#include <memory>
#include <string>
#include <exception>
#include <stdexcept>

namespace net {

class DataSocket;
class TcpSocket : NONCOPYABLE
{
private:
	class TcpSocketDeleter
	{
	public:
		void operator()(TcpSocket* ptr)const
		{
			delete ptr;
		}
	};

public:
	typedef std::unique_ptr<TcpSocket, TcpSocketDeleter> PTR;

public:
	static PTR Create(sock fd, bool serverSide);

public:
	void    SocketNodelay() const;
	bool    SocketNonblock() const;
	void    SetSendSize(int sdSize) const;
	void    SetRecvSize(int rdSize) const;
	std::string GetIP() const;
	bool    isServerSide() const;

private:
	TcpSocket(sock fd, bool serverSide);
	virtual ~TcpSocket();		// 私有只能new
	sock getFD() const;
private:
	const sock mFD;
	const bool mServerSide;
	
	friend class DataSocket;
};

// 函数返回状态
class EintrError : public std::exception
{
};

// 接受错误
class AcceptError : public std::runtime_error
{
public:
	AcceptError(int errorCode)
		: std::runtime_error(std::to_string(errorCode))
		, mErrorCode(errorCode)
	{
	}
	
	int GetErrorCode()const
	{
		return mErrorCode;
	}
private:
	int mErrorCode;
};

class ListenSocket : NONCOPYABLE
{
private:
	class ListenSocketDeleter // 和TcpSocket 重复, 模板
	{
	public:
		void operator()(ListenSocket* ptr)const
		{
			delete ptr;
		}
	};

public:
	typedef std::unique_ptr<ListenSocket, ListenSocketDeleter> PTR;

public:
	static PTR Create(sock fd);
	TcpSocket::PTR Accept();

private:
	explicit ListenSocket(sock fd);
	virtual ~ListenSocket();
private:
	const sock mFD;

	friend class DataSocket;
};

}


#endif // !_SOCKET_H_



