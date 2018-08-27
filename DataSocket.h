#ifndef _DATASOCKET_H_
#define _DATASOCKET_H_

#include <memory>
#include <functional>
#include <deque>
#include <chrono>
#include <any>

#include "channel.h"
#include "EventLoop.h"
#include "NonCopyable.h"
#include "Socket.h"
#include "EventLoop.h"
#include "buffer.h"

#ifdef USE_OPENSSL

#ifdef  __cplusplus
extern "C" {
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef  __cplusplus
}
#endif

#endif

namespace net {

class DataSocket : public Channel, public std::enable_shared_from_this<DataSocket>, NONCOPYABLE 
{
public:
	typedef std::shared_ptr<DataSocket> PTR;
	typedef std::function<void(PTR)>								ENTER_CALLBACK;
	typedef std::function<size_t(const char* buffer, size_t len)>	DATA_CALLBACK;
	typedef std::function<void(PTR)>								DISCONNECT_CALLBACK;
	typedef std::function<void(void)>								PACKED_SENDED_CALLBACK;
	typedef std::shared_ptr<std::string>							PACKET_PTR;

public:
	PTR static Create(TcpSocket::PTR, size_t maxRecvBufferSize, ENTER_CALLBACK, EventLoop::PTR);

	// must called in network thread
	bool onEnterEventLoop();
	const EventLoop::PTR& getEventLoop()const;

	// TODO: ���������EventLoop�Ѿ�û�й���, ����ܵ����ڴ����޴�,��Ϊ��Ͷ�ݵ�����û�еõ�����
	
	void send(const char* buffer, size_t len, const PACKED_SENDED_CALLBACK& callback = nullptr);
	void send(const PACKET_PTR& packet, const PACKED_SENDED_CALLBACK& callback = nullptr);
	void sendInLoop(const PACKET_PTR& packet, const PACKED_SENDED_CALLBACK& callback = nullptr);

	// TODO: �̰߳�ȫ����
	void setDataCallback(DATA_CALLBACK cb);
	void setDisconnectCallback(DISCONNECT_CALLBACK cb);

	// checkTime is zero, cancel check heartbeat
	void setHeardBeat(std::chrono::nanoseconds checkTime);
	void postDisconnect();		// �ر�socket
	void postShutdown();		// push aferloopproc

	void setUD(std::any value);
	const std::any& getUD()const;

	const std::string& getIP()const;

#ifdef USE_OPENSSL
	bool initAcceptSSL(SSL_CTX*);
	bool initConnectSSL();
#endif
	
	static DataSocket::PACKET_PTR makePacket(const char* buffer, size_t len);

protected:
	DataSocket(TcpSocket::PTR socket, size_t maxRecvBufferSize, ENTER_CALLBACK enterCallback, EventLoop::PTR eventLoop)noexcept;
	~DataSocket()noexcept;

private:
	void growRecvBuffer();		// ����ox_buffer
	void PingCheck();
	void StartPingCheckTimer();
	
	void canRecv()override;
	void canSend()override;
	void onClose()override;		// afterloopproc
	
	bool checkRead();			// ���ɶ�(WSARecv(0))
	bool checkWrite();

	void recv();				// ��ȡ����
	void flush();
	void normalFlush();			// flush sendlist
	void quickFlush();			// Linux

	void closeSocket();			// mSocket=nullptr
	void procCloseInLoop();
	void procShutdownInLoop();

	void runAfterFlush();
	void causeEnterCallback();
#ifdef PLATFORM_LINUX
	void removeCheckWrite();
#endif
#ifdef USE_OPENSSL
	bool processSSLHandshake();
#endif
	
private:
#ifdef PLATFORM_WINDOWS
	struct EventLoop::ovl_ext_s		mOvlRecv;
	struct EventLoop::ovl_ext_s		mOvlSend;
	bool							mPostRecvCheck;
	bool							mPostSendCheck;
#endif // PLATFORM_WINDOWS

	const sock						mFD;
	TcpSocket::PTR					mSocket;
	const std::string				mIP;
	const EventLoop::PTR			mEventLoop;
	bool							mCanWrite;

	struct BufferDeleter
	{
		void operator()(struct buffer_s* ptr)const
		{
			ox_buffer_delete(ptr);
		}
	};

	std::unique_ptr<buffer_s, BufferDeleter>	mRecvBuffer;
	const size_t								mMaxRecvBufferSize;

	struct pending_packet
	{
		PACKET_PTR	data;
		size_t		left;
		PACKED_SENDED_CALLBACK mCompleteCallback;
	};
	typedef std::deque<pending_packet> PACKET_LIST_TYPE;

	PACKET_LIST_TYPE						mSendList;
	
	ENTER_CALLBACK							mEnterCallback;
	DATA_CALLBACK							mDataCallback;		// ��ȡ���ݻص�
	DISCONNECT_CALLBACK						mDisconnectCallback;

	bool									mIsPostFlush;
	std::any								mUD;	// �����

	bool									mRecvData;
	std::chrono::nanoseconds				mCheckTime;
	utils::Timer::WeakPtr					mTimer;
	
#ifdef USE_OPENSSL
	SSL_CTX*	mSSLCtx;
	SSL*		mSSL;
	bool		mIsHandSharked;
#endif // USE_OPENSSL


};
}



#endif // !_DATASOCKET_H_