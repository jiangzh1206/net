#include "Connector.h"

#include <map>

namespace net {

class AsyncConnectAddr
{
public:
	AsyncConnectAddr(const std::string& ip, int port, std::chrono::nanoseconds timeout, const AsyncConnector::COMPLETE_CALLBACK& successCB,
		const AsyncConnector::FAILED_CALLBACK& failedCB)
	: mIP(ip), mPort(port), mTimeout(timeout), mSuccessCB(successCB), mFailedCB(failedCB)
	{ }

	const std::string& getIP() const {return mIP;}
	int getPort()const {return mPort;};
	std::chrono::nanoseconds getTimeout() const {return mTimeout;};
	const AsyncConnector::COMPLETE_CALLBACK& getSuccessCB() const {return mSuccessCB;};
	const AsyncConnector::FAILED_CALLBACK& getFailedCB() const {return mFailedCB;};
private:
	std::string							mIP;
	int									mPort;
	std::chrono::nanoseconds			mTimeout;
	AsyncConnector::COMPLETE_CALLBACK	mSuccessCB;
	AsyncConnector::FAILED_CALLBACK		mFailedCB;
};

class ConnectWorkerInfo final : NONCOPYABLE
{
public:
	typedef std::shared_ptr<ConnectWorkerInfo>		PTR;

	ConnectWorkerInfo() noexcept;

	void checkConnectStatus(int millisecond);
	bool isConnectSuccess(sock clientfd, bool willCheckWrite) const;
	void checkTimeout();
	void processConnect(const AsyncConnectAddr&);
	void causeAllFailed();

private:
	struct ConnectingInfo
	{
		ConnectingInfo():timeout(std::chrono::nanoseconds::zero()){}

		std::chrono::steady_clock::time_point	startConnectTime;
		std::chrono::nanoseconds				timeout;
		AsyncConnector::COMPLETE_CALLBACK		successCB;
		AsyncConnector::FAILED_CALLBACK			failedCB;
	};

	std::map<sock, ConnectingInfo> mConnectionInfos;
private:
	struct FDSetDeleter
	{
		void operator()(struct fdset_s* ptr) const {/* ox_fdset_delete(ptr); */}
	};
	struct StackDeleter
	{
		void operator()(struct stack_s* ptr) const {/* ox_stack_delete(ptr); */}
	};

	std::unique_ptr<struct fdset_s, FDSetDeleter> mFDSet;
	std::unique_ptr<struct stack_s, StackDeleter> mPollResult;
};


AsyncConnector::PTR AsyncConnector::Create()
{
	struct make_shared_enabler : public AsyncConnector
	{
	};

	return std::make_shared<make_shared_enabler>();
}

void AsyncConnector::startWorkerThread()
{
}

void AsyncConnector::stopWorkerThread()
{
	std::lock_guard<std::shared_mutex> lk(mThreadGuard);
	if (mThread == nullptr) {
		return;
	}

	mEventLoop->pushAsyncProc([this](){		// ÍÆËÍµ½eventloop
		*mIsRun = false;
	});

	try {
		if (mThread->joinable()) {
			mThread->join();
		}
	} catch (...) {
	}

	mEventLoop = nullptr;
	mWorkInfo = nullptr;
	mIsRun = nullptr;
	mThread = nullptr;
}

void AsyncConnector::asyncConnect(const std::string & ip, int port, std::chrono::nanoseconds timeout, 
	COMPLETE_CALLBACK completeFunc, FAILED_CALLBACK failedFunc)
{
}

AsyncConnector::AsyncConnector() noexcept
{
	mIsRun = std::make_shared<bool>(false);
}

AsyncConnector::~AsyncConnector() noexcept
{
	stopWorkerThread();
}

}
