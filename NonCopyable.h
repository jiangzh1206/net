#ifndef _NONCOPYABLE_H_
#define _NONCOPYABLE_H_

#define NONCOPYABLE private net::NonCopyable

namespace net {

class NonCopyable
{
protected:
	NonCopyable() = default;
	~NonCopyable() = default;

	NonCopyable(const NonCopyable&) = delete;
	const NonCopyable& operator=(const NonCopyable&) = delete;
};


}




#endif // !_NONCOPYABLE_H_



