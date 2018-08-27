#ifndef _TCPSERVER_H_
#define _TCPSERVER_H_

#include <string>
#include <thread>

#include "NonCopyable.h"
#include "EventLoop.h"
#include "DataSocket.h"


namespace net {

class EventLoop;
class IOLoopData;
typedef std::shared_ptr<IOLoopData> IOLoopDataPtr;

class TCPService : public std::enable_shared_from_this<TCPService>, NONCOPYABLE
{
public:
	typedef std::shared_ptr<TCPService>					PTR;
	typedef std::function<void(const EventLoop::PTR&)>	FRAME_CALLBACK;		// start 线程回调
	typedef std::function<void(const DataSocket::PTR&)>	ENTER_CALLBACK;

	class AddSocketOption
	{
	public:
		struct Options{
			Options() {
				useSSL = false;
				forceSameThreadLoop = false;
				maxRecvBufferSize = 0;
			}

			TCPService::ENTER_CALLBACK	enterCallback;
			//SSLHelper::PTR			sslHelper;
			bool						useSSL;
			bool						forceSameThreadLoop;
			size_t						maxRecvBufferSize;
		};

		typedef std::function<void(Options& option)> AddSocketOptionFunc;

		static AddSocketOptionFunc WithEnterCallback(TCPService::ENTER_CALLBACK callback);
		static AddSocketOptionFunc WithClientSideSSL();
		//static AddSocketOptionFunc WithServerSideSSL(SSLHelper::PTR sslHelper);
		static AddSocketOptionFunc WithMaxRecvBufferSize(size_t size);
		static AddSocketOptionFunc WithForceSameThreadLoop(bool same);
	};

public:
	static PTR Create();
	void startWorkerThread(size_t threadNum, FRAME_CALLBACK callback = nullptr);
	void stopWorkerThread();
	
	EventLoop::PTR getRandomEventLoop();

	template<typename... Options>
	bool addDataSockets(TcpSocket::PTR socket, const Options& ... options)		// 多个option
	{
		return _addDataSockets(std::move(socket), {options...});
	}

protected:
	bool _addDataSockets(TcpSocket::PTR, const std::vector<AddSocketOption::AddSocketOptionFunc>&);
	EventLoop::PTR getSameThreadEventLoop();

	TCPService() noexcept;
	~TCPService() noexcept;

private:
	std::vector<IOLoopDataPtr>			mIOLoopDatas;
	mutable std::mutex					mIOLoopGuard;
	std::shared_ptr<bool>				mRunIOLoop;		// 工作线程取值判读是否执行
	std::mutex							mServiceGuard;
};



} // namespace net





#endif // !_TCPSERVER_H_

