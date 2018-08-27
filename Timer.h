#ifndef _TIMER_H_
#define _TIMER_H_

#include <functional>
#include <queue>
#include <memory>
#include <vector>
#include <chrono>


namespace utils {
namespace CN = std::chrono;

class TimerMgr;

class Timer
{
public:
	typedef std::shared_ptr<Timer>			Ptr;
	typedef std::weak_ptr<Timer>			WeakPtr;
	typedef std::function<void(void)>		Callback;

public:
	Timer(CN::steady_clock::time_point start, CN::nanoseconds last, Callback f) noexcept;

	const CN::steady_clock::time_point& getStartTime() const ;
	const CN::nanoseconds& getLastTime()const;

	CN::nanoseconds getLeftTime()const;
	void cancel();

private:
	void operator()();

private:
	bool							mActive;
	Callback						mCallback;
	CN::steady_clock::time_point	mStartTime;
	CN::nanoseconds					mLastTime;

	friend class TimerMgr;
};


class TimerMgr
{
public:
	typedef std::shared_ptr<TimerMgr> PTR;

	template<typename F, typename... Args>
	Timer::WeakPtr addTimer(CN::nanoseconds timeout, F callback, Args&&...args)
	{
		auto timer = std::make_shared<Timer>(CN::steady_clock::now(), CN::nanoseconds(timeout),
			std::bind(std::move(callback), std::forward<Args>(args)...));
		mTimers.push(timer);

		return timer;
	}

	void schedule();
	bool isEmpty()const;
	CN::nanoseconds nearLeftTime()const;
	void clear();

private:
	struct CompareTimer
	{
		bool operator()(const Timer::Ptr& left, const Timer::Ptr& right) const
		{
			const auto startDiff = left->getStartTime() - right->getStartTime();
			const auto lastDiff = left->getLastTime() - right->getLastTime();
			const auto diff = startDiff.count()	 + lastDiff.count();

			return diff > 0;
		}
	};

	std::priority_queue<Timer::Ptr, std::vector<Timer::Ptr>, CompareTimer> mTimers;

};

}


#endif // !_TIMER_H_



