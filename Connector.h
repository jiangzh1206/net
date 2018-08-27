#ifndef _CONNECTOR_H_
#define _CONNECTOR_H_

#include <functional>
#include <memory>
#include <any>
#include <shared_mutex>


#include "SocketLibFunction.h"
#include "NonCopyable.h"
#include "Socket.h"
#include "EventLoop.h"


namespace net {

class ConnectWorkerInfo;

class AsyncConnector : public std::enable_shared_from_this<AsyncConnector>, NONCOPYABLE
{
public:
	typedef std::shared_ptr<AsyncConnector>			PTR;
	typedef std::function<void(TcpSocket::PTR)>		COMPLETE_CALLBACK;
	typedef std::function<void()>					FAILED_CALLBACK;

	static PTR Create();
	
	void startWorkerThread();
	void stopWorkerThread();
	void asyncConnect(const std::string& ip, int port, std::chrono::nanoseconds timeout, 
		COMPLETE_CALLBACK completeFunc, FAILED_CALLBACK failedFunc);

private:
	AsyncConnector() noexcept;
	virtual ~AsyncConnector() noexcept;

	std::shared_ptr<EventLoop>				mEventLoop;
	std::shared_ptr<ConnectWorkerInfo>		mWorkInfo;
	std::shared_ptr<std::thread>			mThread;
	std::shared_mutex						mThreadGuard;	// 一个或多个读线程同时读取共享资源，且只有一个写线程来修改这个资源
	std::shared_ptr<bool>					mIsRun;

};


}


#endif // !_CONNECTOR_H_





