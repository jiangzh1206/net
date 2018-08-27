#ifndef _LISTENTHRAD_H_
#define _LISTENTHRAD_H_

#include <string>
#include <functional>
#include <thread>
#include <mutex>
#include <memory>

#include "NonCopyable.h"
#include "SocketLibFunction.h"
#include "Socket.h"

namespace net {



class ListenThread : public std::enable_shared_from_this<ListenThread>, NONCOPYABLE
{
public:
	typedef std::shared_ptr<ListenThread>				PTR;
	typedef std::function<void(TcpSocket::PTR)>			ACCEPT_CALLBACK;
	
	static PTR Create();

	void startListen(bool isIPV6, const std::string& IP, int port, ACCEPT_CALLBACK callback);
	void stopLissten();


private:
	ListenThread() noexcept;
	virtual ~ListenThread() noexcept;

private:
	bool							mIsIPV6;
	std::string						mIP;
	int								mPort;
	std::shared_ptr<bool>			mRunListen;
	std::shared_ptr<std::thread>	mListenThread;
	std::mutex						mListenThreadGuard;
};

}


#endif // !_LISTENTHRAD_H_





