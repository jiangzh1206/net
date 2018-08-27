#include "TCPServer.h"
#include "EventLoop.h"

const static unsigned int sDefaultLoopTimeOutMS = 100;		// 毫秒

namespace net {

class IOLoopData :  public std::enable_shared_from_this<IOLoopData>, NONCOPYABLE
{
public:
	typedef std::shared_ptr<IOLoopData> PTR;

public:
	static PTR Create(EventLoop::PTR eventLoop, std::shared_ptr<std::thread> ioThread)
	{
		struct shared_ptr_enabler : public IOLoopData
		{
			shared_ptr_enabler(EventLoop::PTR eventLoop, std::shared_ptr<std::thread> ioThread)
				: IOLoopData(std::move(eventLoop), std::move(ioThread)){ 
			}
		};
		return std::make_shared<shared_ptr_enabler>(std::move(eventLoop), std::move(ioThread));
	}

	EventLoop::PTR getEventLoop()
	{
		return mEventLoop;
	}
private:
	std::shared_ptr<std::thread> getIOThread()
	{
		return mIOThread;
	}

	explicit IOLoopData(EventLoop::PTR eventLoop, std::shared_ptr<std::thread> ioThread)
		: mEventLoop(std::move(eventLoop)), mIOThread(std::move(ioThread))
	{
	}

	virtual ~IOLoopData() = default;
private:
	const EventLoop::PTR			mEventLoop;
	std::shared_ptr<std::thread>	mIOThread;

	friend class TCPService;
};

//-------------------------------------------------------------------------------------------------

TCPService::PTR TCPService::Create()
{
	struct shared_ptr_enalber : public TCPService{};
	return std::make_shared<shared_ptr_enalber>();
}

void TCPService::startWorkerThread(size_t threadNum, FRAME_CALLBACK callback)
{
	std::lock_guard<std::mutex> lk0(mServiceGuard);
	std::lock_guard<std::mutex> lk1(mIOLoopGuard);

	if (!mIOLoopDatas.empty()) {
		return;		// 启动时loopdata为空
	}

	mRunIOLoop = std::make_shared<bool>(true);
	mIOLoopDatas.resize(threadNum);
	for (auto& loopdata : mIOLoopDatas) {
		auto eventLoop = std::make_shared<EventLoop>();
		auto runLoop = mRunIOLoop;

		loopdata = IOLoopData::Create(eventLoop, std::make_shared<std::thread>([callback, runLoop, eventLoop](){
			while (*runLoop) {
				auto timeout = std::chrono::milliseconds(sDefaultLoopTimeOutMS);
				if (!eventLoop->getTimerMgr()->isEmpty()) {
					timeout = std::chrono::duration_cast<std::chrono::milliseconds>(eventLoop->getTimerMgr()->nearLeftTime());
				}
				eventLoop->loop(timeout.count());
				if (callback != nullptr) {
					callback(eventLoop);
				}
			}
		}));
	}
}

void TCPService::stopWorkerThread()
{
	std::lock_guard<std::mutex> lk0(mServiceGuard);
	std::lock_guard<std::mutex> lk1(mIOLoopGuard);

	*mRunIOLoop = false;
	for (const auto& loop : mIOLoopDatas) {
		loop->getEventLoop()->wakeup();
		try {
			if (loop->getIOThread()->joinable()) {
				loop->getIOThread()->join();
			}
		} catch (...) {

		}
	}

	mIOLoopDatas.clear();
}

EventLoop::PTR TCPService::getRandomEventLoop()
{
	const auto randNum = rand();
	std::lock_guard<std::mutex> lk(mIOLoopGuard);
	if (mIOLoopDatas.empty()) {
		return nullptr;
	}

	return mIOLoopDatas[randNum % mIOLoopDatas.size()]->getEventLoop();
}

bool TCPService::_addDataSockets(TcpSocket::PTR socket, const std::vector<AddSocketOption::AddSocketOptionFunc>& optionFuncs)
{
	struct TCPService::AddSocketOption::Options options;
	for (const auto& v : optionFuncs) {
		if (v != nullptr) {
			v(options);			// 传进引用处理options
		}
	}

	if (options.maxRecvBufferSize <= 0) {
		throw std::runtime_error("buffer size is zero.");
	}

	EventLoop::PTR eventLoop;
	if (options.forceSameThreadLoop) {
		eventLoop = getSameThreadEventLoop();
	} else {
		eventLoop = getRandomEventLoop();
	}

	if (eventLoop == nullptr) {
		return false;
	}

	const auto isServerSide = socket->isServerSide();
	auto dataSocket = DataSocket::Create(std::move(socket), options.maxRecvBufferSize, options.enterCallback, eventLoop);
#ifdef USE_OPENSSL

#else
	if (options.useSSL) {
		return false;
	}
#endif // USE_OPENSSL
	eventLoop->pushAsyncProc([dataSocket](){
		dataSocket->onEnterEventLoop();		// 加入eventloop
	});

	return false;
}

EventLoop::PTR TCPService::getSameThreadEventLoop()
{
	std::lock_guard<std::mutex> lock(mIOLoopGuard);
	for (const auto& v : mIOLoopDatas) {
		if (v->getEventLoop()->isInLoopThread()) {
			return v->getEventLoop();
		}
	}
	return nullptr;
}

TCPService::TCPService() noexcept
{
	mRunIOLoop = std::make_shared<bool>(false);
}


TCPService::~TCPService() noexcept
{
	stopWorkerThread();
}


TCPService::AddSocketOption::AddSocketOptionFunc TCPService::AddSocketOption::WithEnterCallback(TCPService::ENTER_CALLBACK callback)
{
	return [=](TCPService::AddSocketOption::Options& option) {
		option.enterCallback = callback;
	};
}

TCPService::AddSocketOption::AddSocketOptionFunc TCPService::AddSocketOption::WithClientSideSSL()
{
	return [=](TCPService::AddSocketOption::Options& option) {
		option.useSSL = true;
	};
}

TCPService::AddSocketOption::AddSocketOptionFunc TCPService::AddSocketOption::WithMaxRecvBufferSize(size_t size)
{
	return [=](TCPService::AddSocketOption::Options& option) {
		option.maxRecvBufferSize = size;
	};
}

TCPService::AddSocketOption::AddSocketOptionFunc TCPService::AddSocketOption::WithForceSameThreadLoop(bool same)
{
	return [=](TCPService::AddSocketOption::Options& option) {
		option.forceSameThreadLoop = same;
	};
}

} // namespace net


