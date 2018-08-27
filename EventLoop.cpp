#include "EventLoop.h"


namespace net {

class WakeupChannel final : public Channel, NONCOPYABLE
{
public:
	explicit WakeupChannel(HANDLE iocp)
		: mIOCP(iocp), mWakeupOvl(EventLoop::OLV_VALUE::OLV_RECV)
	{
	}

	void wakeup()noexcept
	{
		PostQueuedCompletionStatus(mIOCP, 0, reinterpret_cast<ULONG_PTR>(this), &mWakeupOvl.base);
	}
private:
	void canSend()noexcept override
	{
	}

	void canRecv()noexcept override
	{
	}
	
	void onClose()noexcept override
	{
	}

private:
	HANDLE mIOCP;
	EventLoop::ovl_ext_s mWakeupOvl;
};


EventLoop::EventLoop() noexcept		// 创建完成端口
	: mIOCP(CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 1))
	, mWakeupChannel(std::make_unique<WakeupChannel>(mIOCP))
{
	mPGetQueuedCompletionStatusEx = nullptr;
	auto kernel32_modul = GetModuleHandleA("kernel32.dll");
	if (NULL != kernel32_modul) {
		mPGetQueuedCompletionStatusEx = (sGetQueuedCompletionStatusEx)GetProcAddress(kernel32_modul, "GetQueuedCompletionStatusEx");

		FreeLibrary(kernel32_modul);
	}

	mIsAlreadyPostWakeup = false;
	mIsInBlock = true;
	reallocEventSize(1024);
	mSelfThreadID = -1;
	mTimer = std::make_shared<utils::TimerMgr>();
}


EventLoop::~EventLoop()
{
	CloseHandle(mIOCP);
	mIOCP = INVALID_HANDLE_VALUE;
}

void EventLoop::loop(int64_t milliseconds)
{
	tryInitThreadId();
#ifndef NDEBUG
	assert(isInLoopThread());
#endif // !NDEBUG
	if (!isInLoopThread()) {
		return;
	}
	if (!mAfterLoopProcs.empty()) {
		milliseconds = 0;
	}

	// 检查完成状态
	ULONG numComplete = 0;
	if (mPGetQueuedCompletionStatusEx != nullptr) {
		if (!mPGetQueuedCompletionStatusEx(mIOCP, mEventEntries.data(), mEventEntries.size(), &numComplete, DWORD(milliseconds), false)) {
			numComplete = 0;
		}
	} else {
		for (auto& e : mEventEntries) {
			const auto timeout = DWORD(milliseconds);
			/*不检查GOCS返回值*/
			GetQueuedCompletionStatus(mIOCP, &e.dwNumberOfBytesTransferred, &e.lpCompletionKey, &e.lpOverlapped, timeout);

			if (e.lpOverlapped == nullptr) {
				break;
			}
			++numComplete;
		}
	}

	mIsInBlock = false;

	for (ULONG i = 0; i < numComplete; ++i) {
		auto channel = (Channel*)mEventEntries[i].lpCompletionKey;
		assert(channel != nullptr);
		const auto ovl = reinterpret_cast<const EventLoop::ovl_ext_s*>(mEventEntries[i].lpOverlapped);
		if (ovl->OP == EventLoop::OLV_VALUE::OLV_RECV) {
			channel->canRecv();		// 调用DataSocket接收数据
		} else if (ovl->OP == EventLoop::OLV_VALUE::OLV_SEND) {
			channel->canSend();
		} else {
			assert(false);
		}
	
	}

	mIsAlreadyPostWakeup = false;
	mIsInBlock = true;

	processAsyncProc();
	processAfterLoopProc();

	if (static_cast<size_t>(numComplete) == mEventEntries.size()) {
		reallocEventSize(mEventEntries.size() + 128);
	}

	mTimer->schedule();
}

bool EventLoop::wakeup()
{
	// mIsBlock true mIsAlreadyPostWakeup fasle  添加IO操作
	if (!isInLoopThread() && mIsInBlock && !mIsAlreadyPostWakeup.exchange(true)) {
		mWakeupChannel->wakeup();
	}
	return false;
}

void EventLoop::pushAsyncProc(USER_PROC f)
{
	if (isInLoopThread()) {
		f();
	} else {
		{
			std::lock_guard<std::mutex> lk(mAsyncProcsMutex);
			mAsyncProcs.emplace_back(std::move(f));
		}
		wakeup();
	}
}

void EventLoop::pushAfterLoopProc(USER_PROC f)
{
	assert(isInLoopThread());
	if (isInLoopThread()) {
		mAfterLoopProcs.emplace_back(std::move(f));
	}
}

utils::TimerMgr::PTR EventLoop::getTimerMgr()
{
	// 构造函数中创建mTimer
	tryInitThreadId();
	assert(isInLoopThread());
	return isInLoopThread() ? mTimer : nullptr;
}

void EventLoop::reallocEventSize(size_t size)
{
	mEventEntries.resize(size);
}

void EventLoop::processAfterLoopProc()
{
	mCopyAfterLoopProcs.swap(mAfterLoopProcs); // copy 处理执行proc, 未加锁?
	for (auto& x : mCopyAfterLoopProcs) {
		x();
	}
	mCopyAfterLoopProcs.clear();
}

void EventLoop::processAsyncProc()
{
	{
		std::lock_guard<std::mutex> lk(mAsyncProcsMutex);	// 加锁
		mCopyAsyncProcs.swap(mAsyncProcs);
	}
	for (const auto& proc : mCopyAsyncProcs) {
		proc();
	}
	mCopyAsyncProcs.clear();
}

bool EventLoop::linkChannel(sock fd, const Channel * ptr) noexcept
{
	// socket 绑定完成端口, completionkey 为Channel*
	return CreateIoCompletionPort((HANDLE)fd, mIOCP, (ULONG_PTR)ptr, 0) != nullptr;
}

DataSocketPtr EventLoop::getDataSocketPtr(sock fd)
{
	auto it = mDataSockets.find(fd);
	if (it != mDataSockets.end()) {
		return (*it).second;
	}
	return nullptr;
}

void EventLoop::addDataSocket(sock fd, DataSocketPtr datasocket)
{
	mDataSockets[fd] = datasocket;
}

void EventLoop::removeDataSocket(sock fd)
{
	mDataSockets.erase(fd);
}

void EventLoop::tryInitThreadId()
{
	std::call_once(mOnceInitThreadID, [this](){
		mSelfThreadID = CurrentThread::tid();
	});
}

}

