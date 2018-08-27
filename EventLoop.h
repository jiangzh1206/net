#ifndef _EVENTLOOP_H_
#define _EVENTLOOP_H_

#define PLATFORM_WINDOWS

#include <memory>
#include <functional>
#include <vector>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <cassert>

#include "NonCopyable.h"
#include "CurrentThread.h"
#include "channel.h"
#include "Timer.h"

typedef SOCKET sock;

namespace net {

class Channel;
class DataSocket;
class WakeupChannel;
typedef std::shared_ptr<DataSocket> DataSocketPtr;


class EventLoop : NONCOPYABLE
{
public:
	typedef std::shared_ptr<EventLoop>	PTR;
	typedef std::function<void(void)>	USER_PROC;

#ifdef PLATFORM_WINDOWS
	enum class OLV_VALUE	// overlapped value
	{
		OLV_ONOE = 0,
		OLV_RECV,
		OLV_SEND,
	};

	struct ovl_ext_s		// 标志绑定每一个IO操作, OVERLAPPED必须,其他自定义
	{
		OVERLAPPED base;
		const EventLoop::OLV_VALUE OP;

		ovl_ext_s(OLV_VALUE op) noexcept
			: OP(op)
		{
			memset(&base, 0, sizeof(base));
		}
	};
#endif

public:
	EventLoop() noexcept;
	virtual ~EventLoop() noexcept;
	void loop(int64_t milliseconds);
	bool wakeup();
	void pushAsyncProc(USER_PROC f);
	void pushAfterLoopProc(USER_PROC f);
	/* return nullptr if not called in net thread*/
	utils::TimerMgr::PTR getTimerMgr();

	inline bool isInLoopThread() const
	{
		return mSelfThreadID == CurrentThread::tid(); // 自身ID等于current ID(在当前线程)
	}

private:
	void reallocEventSize(size_t size);
	void processAfterLoopProc();
	void processAsyncProc();

private:
	bool linkChannel(sock fd, const Channel* ptr) noexcept;
	DataSocketPtr getDataSocketPtr(sock fd);
	void addDataSocket(sock fd, DataSocketPtr);
	void removeDataSocket(sock fd);
	void tryInitThreadId();

private:
	std::vector<OVERLAPPED_ENTRY>	mEventEntries;
	typedef BOOL(WINAPI *sGetQueuedCompletionStatusEx) (HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL);
	sGetQueuedCompletionStatusEx	mPGetQueuedCompletionStatusEx;
	HANDLE mIOCP;
	std::unique_ptr<WakeupChannel>	mWakeupChannel;
	std::atomic_bool				mIsInBlock;
	std::atomic_bool				mIsAlreadyPostWakeup;

	std::mutex						mAsyncProcsMutex;
	std::vector<USER_PROC>			mAsyncProcs;
	std::vector<USER_PROC>			mCopyAsyncProcs;
	std::vector<USER_PROC>			mAfterLoopProcs;
	std::vector<USER_PROC>			mCopyAfterLoopProcs;

	std::once_flag					mOnceInitThreadID;	// 初始化一次
	CurrentThread::THREAD_ID_TYPE	mSelfThreadID;		// thread_local

	utils::TimerMgr::PTR					mTimer;
	std::unordered_map<sock, DataSocketPtr> mDataSockets;
	
	friend class DataSocket;
};
}



#endif // _EVENTLOOP_H_

