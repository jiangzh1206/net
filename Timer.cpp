#include "Timer.h"

using namespace std::chrono;

namespace utils {

Timer::Timer(CN::steady_clock::time_point start, CN::nanoseconds last, Callback f) noexcept
	: mActive(true)
	, mCallback(std::move(f))
	, mStartTime(std::move(start))
	, mLastTime(std::move(last))
{
}

const CN::steady_clock::time_point & Timer::getStartTime() const
{
	return mStartTime;
}

const CN::nanoseconds & Timer::getLastTime() const
{
	return mLastTime;
}

CN::nanoseconds Timer::getLeftTime() const
{
	return getLastTime() - (steady_clock::now() - mStartTime);
}

void Timer::cancel()
{
	mActive = false;
}

void Timer::operator()()
{
	if (mActive) {
		mCallback();
	}
}

void TimerMgr::schedule()
{
	while (!mTimers.empty()) {
		auto temp = mTimers.top();
		if (temp->getLeftTime() > nanoseconds::zero()) {
			break;
		}

		mTimers.pop();
		(*temp)();
	}
}

bool TimerMgr::isEmpty() const
{
	return mTimers.empty();
}

CN::nanoseconds TimerMgr::nearLeftTime() const
{
	if (mTimers.empty()) {
		return nanoseconds::zero();
	}

	auto result = mTimers.top()->getLeftTime();
	if (result < nanoseconds::zero()) {
		return nanoseconds::zero();
	}
	
	return result;
}
void TimerMgr::clear()
{
	while (!mTimers.empty()) {
		mTimers.pop();
	}
}


} // namespace utils


