#ifndef _CHANNEL_H_
#define _CHANNEL_H_

namespace net {

class EventLoop;

class Channel
{
public:
	virtual ~Channel() = default;

private:
	virtual void    canSend() = 0;
	virtual void    canRecv() = 0;
	virtual void    onClose() = 0;

	friend class EventLoop; // 纯虚定义成了private, 用了友元, ?
};


}


#endif // !_CHANNEL_H_
