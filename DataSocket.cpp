#include "DataSocket.h"
#include "SocketLibFunction.h"

namespace net {

const static size_t GROW_BUFFER_SIZE = 1024;

DataSocket::PACKET_PTR DataSocket::makePacket(const char * buffer, size_t len)
{
	return DataSocket::PACKET_PTR();
}

DataSocket::DataSocket(TcpSocket::PTR socket, size_t maxRecvBufferSize, ENTER_CALLBACK enterCallback, EventLoop::PTR eventLoop) noexcept
	: 
#ifdef  PLATFORM_WINDOWS
	mOvlRecv(EventLoop::OLV_VALUE::OLV_RECV),
	mOvlSend(EventLoop::OLV_VALUE::OLV_SEND),
#endif //  PALTFORM_WINDOWS
	mFD(socket->getFD()),
	mIP(socket->GetIP()),
	mEventLoop(eventLoop),
	mMaxRecvBufferSize(maxRecvBufferSize)
{
	mRecvData = false;
	mCheckTime = std::chrono::steady_clock::duration::zero();
	mIsPostFlush = false;
	mSocket = std::move(socket);
	mCanWrite = true;

#ifdef PLATFORM_WINDOWS
	mPostRecvCheck = false;
	mPostSendCheck = false;
#endif // PLATFORM_WINDOWS

	growRecvBuffer();

#ifdef USE_OPENSSL
	mSSLCtx = nullptr;
	mSSL = nullptr;
	mIsHandsharked = false;
#endif
	mEnterCallback = enterCallback;
}

DataSocket::~DataSocket()noexcept
{
#ifdef USE_OPENSSL
	if (mSSL != nullptr) {
		SSL_free(mSSL);
		mSSL = nullptr;
	}
	if (mSSLCtx != nullptr) {
		SSL_CTX_free(mSSLCtx);
		mSSLCtx = nullptr;
	}
#endif

	if (mTimer.lock()) {	// ����Ϊshared_ptr(ָ�����)
		mTimer.lock()->cancel();
	}
}

void DataSocket::growRecvBuffer()
{
	if (mRecvBuffer == nullptr) {
		mRecvBuffer.reset(ox_buffer_new(16 * 1024 * GROW_BUFFER_SIZE));
	} else {
		const auto newSize = ox_buffer_getsize(mRecvBuffer.get()) + GROW_BUFFER_SIZE;
		if (newSize > mMaxRecvBufferSize) {		// ����ʱ�������size
			return;
		}

		std::unique_ptr<struct buffer_s, BufferDeleter> newBuffer(ox_buffer_new(newSize));
		ox_buffer_write(newBuffer.get(), ox_buffer_getreadptr(mRecvBuffer.get()), 
			ox_buffer_getreadvalidcount(mRecvBuffer.get()));		// δ��ȡ��д�뵽newBuffer
		mRecvBuffer = std::move(newBuffer);
	}
}

void DataSocket::PingCheck()
{
	mTimer.reset();
	if (mRecvData) {
		mRecvData = false;
		StartPingCheckTimer();
	} else {
		procCloseInLoop();	// δ���յ����� �ر�socket
	}
}

void DataSocket::StartPingCheckTimer()
{
	// timer �մ���
	if (!mTimer.lock() && mCheckTime != std::chrono::steady_clock::duration::zero()) {
		auto self(shared_from_this());
		mTimer = mEventLoop->getTimerMgr()->addTimer(mCheckTime, [self](){
			self->PingCheck();
		});
	}
}

void DataSocket::canRecv()
{
#ifdef PLATFORM_WINDOWS
	mPostRecvCheck = false;
	if (mSocket != nullptr && !mPostSendCheck) {
		onClose();
	}
#endif // PLATFORM_WINDOWS
#ifdef USE_OPENSLL
	if (!mIsHandsharked && mSSL != nullptr) {
		if (!processSSLHandshake() || !mIsHandsharked) {
			return;
		}
}
#endif // USE_OPENSLL
	recv();
}

void DataSocket::canSend()
{
#ifdef PLATFORM_WINDOWS
	mPostSendCheck = false;	// û��Ͷ��send(WSASend)
	if (mSocket != nullptr && !mPostRecvCheck) { // û��Ͷ��WSARecv �ر�socket
		onClose();
	}
#else
	removeCheckWrite();
#endif // PLATFORM_WINDOWS
	mCanWrite = true;

#ifdef USE_OPENSLL
	if (!mIsHandsharked && mSSL != nullptr) {
		if (!processSSLHandshake() || !mIsHandsharked) {
			return;
		}
	}
#endif // USE_OPENSLL
	runAfterFlush(); //push afterproc flush
}

void DataSocket::onClose()
{
	assert(mEnterCallback == nullptr);
	auto callBack = mDisconnectCallback;
	auto sharedThis = shared_from_this();
	auto eventLoop = mEventLoop;
	auto fd = mFD;

	// ����loop��
	mEventLoop->pushAfterLoopProc([callBack, sharedThis, eventLoop, fd](){
		if (callBack != nullptr) {
				callBack(sharedThis);
			}
		auto tfd = eventLoop->getDataSocketPtr(fd);
		assert(tfd == sharedThis);
		if (tfd == sharedThis) {
			eventLoop->removeDataSocket(fd);
		}
	});

	closeSocket();
	mDisconnectCallback = nullptr;
	mDataCallback = nullptr;
}

bool DataSocket::checkRead() //�Ƿ�Ͷ��recv
{
	bool checkRet = true;

#ifdef PLATFORM_WINDOWS
	static CHAR temp[] = {0};
	static WSABUF in_buf = {0};
	if (mPostRecvCheck) {
		return checkRet;
	}

	DWORD dwBytes = 0;
	DWORD flag = 0;
	const int ret = WSARecv(mSocket->getFD(), &in_buf, 1, &dwBytes, &flag, &(mOvlRecv.base), 0); // Ͷ��recv����
	if (ret == SOCKET_ERROR) {
		checkRet = (sErrno == WSA_IO_PENDING); // Ͷ�ݳɹ�,TCP/IP��������
	}

	if (checkRet) {
		mPostRecvCheck = true;
	}
#endif
	return checkRet;
}

bool DataSocket::checkWrite() //�Ƿ�Ͷ��send
{
	bool checkRet = true;
#ifdef PLATFORM_WINDOWS
	static WSABUF wsendbuf[1] = {{NULL, 0}}; // ����{0,0}
	if (mPostSendCheck) {	// ���Ͷ����send
		return checkRet;
	}

	/*���������ϣ���ܴ���ǳ��ಢ������,������ÿ�����ӵĶ�����ʱͶ��һ��0�ֽڵĶ�����,
	����WSARecv��ʱ��ΪlpBuffers�� dwBufferCount�ֱ𴫵�NULL��0����.�������Ͳ�������ڴ�������������Դ��������,
	����ϵ ͳ�ͻ�Ͷ�����֪ͨ.���ʱ�����˾Ϳ���ȥ�׽��ֽ��ܻ�����ȡ������,�����ַ������Ե�֪�����ж������ݿ��Զ�,
	һ����ͨ��ioctlsocket��� FIONREAD����ȥ"��ѯ",��һ�־���һֱ��,ֱ���õ�WSAEWOULDBLOCK�� ��,�ͱ�ʾû�����ݿɶ���
	����0�� �ڷ��ͷ�ʽ��,Ӧ�ò���Ͷ��һ���յ�WSASend,��ʾϣ����������,����ϵͳһ���ж�������ӿ���д��,
	��Ͷ��һ�����֪ͨ,��ʱ����Է���Ͷ���� ��,���ҷ��ͻ������Ĵ�С�ǿ�֪��,��������ڴ�����������
	*/

	DWORD len = 0;
	const int ret = WSASend(mSocket->getFD(), wsendbuf, 1, &len, 0, &(mOvlRecv.base), 0); // Ͷ��recv����
	if (ret == SOCKET_ERROR) {
		checkRet = (sErrno == WSA_IO_PENDING); // Ͷ�ݳɹ�,TCP/IP��������
	}

	if (checkRet) {
		mPostSendCheck = true;
	}
#else
	struct epoll_event ev = {0, { 0 }};
	ev.events = EPOLLET | EPOLLIN | EPOLLOUT | EPOLLRDHUP;
	ev.data.ptr = (Channel*)(this);
	epoll_ctl(mEventLoop->getEpollHandle(), EPOLL_CTL_MOD, mSocket->getFD(), &ev);
#endif
	return checkRet;
}

void DataSocket::recv()
{
	bool must_close = false;
#ifdef USE_OPENSSL
	const bool notInSSL = (mSSL == nullptr);
#else
	const bool notInSSL = false;
#endif
	while(mSocket != nullptr) {
		const auto tryRecvLen = ox_buffer_getwritevalidcount(mRecvBuffer.get());	// ��д��len
		if (0 == tryRecvLen) {
			break;
		}

		int retLen = 0;
#ifdef USE_OPENSSL

#else
		retLen = ::recv(mSocket->getFD(), ox_buffer_getwriteptr(mRecvBuffer.get()), static_cast<int>(tryRecvLen), 0);
#endif // USE_OPENSSL
		if (0 == retLen) {		// ������ֹ
			must_close = true;
			break;
		} else if (retLen < 0) {
			if (sErrno != S_EWOULDBLOCK) {
				must_close = false;
			} else {
				must_close = !checkRead();		// �ڶ��ν�����ɶ�,����ѭ��
			}
			break;
		} // ��ȡ�Ƿ�ɹ�

		ox_buffer_addwritepos(mRecvBuffer.get(), retLen);
		if (ox_buffer_getreadvalidcount(mRecvBuffer.get()) == ox_buffer_getsize(mRecvBuffer.get())) {
			growRecvBuffer();		// δ���ĵ�������size,������buffer size
		}

		if (mDataCallback != nullptr) {
			mRecvData = true;
			auto procLen = mDataCallback(ox_buffer_getreadptr(mRecvBuffer.get()), 
				ox_buffer_getreadvalidcount(mRecvBuffer.get()));		// ���ش�����

			assert(procLen <= ox_buffer_getreadvalidcount(mRecvBuffer.get()));
			if (procLen <= ox_buffer_getreadvalidcount(mRecvBuffer.get())) {
				ox_buffer_addreadpos(mRecvBuffer.get(), procLen);
			} else {
				break;
			}
		} // ����datacallback ����recvbuffer

		if(ox_buffer_getwritevalidcount(mRecvBuffer.get()) == 0 || ox_buffer_getreadvalidcount(mRecvBuffer.get()) == 0) {
			ox_buffer_ajustto_head(mRecvBuffer.get());		// ��д=0,δ��=0, ����buffer
		}

		if (notInSSL && retLen < static_cast<int>(tryRecvLen)) {
			must_close = !checkRead();		// ��ȡ������ < buffer�ɶ��ĳ���, ����Ƿ�ɶ�
			break;
		}
	}
	if (must_close) {
		procCloseInLoop();
	}
}

void DataSocket::flush()
{
	if (!mCanWrite || mSocket == nullptr) {
		return;
	}

#ifdef PLATFORM_WINDOWS
	normalFlush();
#else
#ifdef USE_OPENSSL
	if (mSSL != nullptr) {
		normalFlush();
	} else {
		quickFlush();
	}
#else
	quickFlush();
#endif
#endif
}

#ifdef PLATFORM_WINDOWS // �̱߳��ر���
thread_local char* threadLocalSendBuf = nullptr;
#else
__thread char* threadLocalSendBuf = nullptr;
#endif // PLATFORM_WINDOWS


void DataSocket::normalFlush()
{
	static const int SENDBUF_SIZE = 1024 * 32;
	if (threadLocalSendBuf == nullptr) {
		threadLocalSendBuf = (char*)malloc(SENDBUF_SIZE);
	}

#ifdef USE_OPENSSL
	const bool notInSSL = (mSSL == nullptr);
#else 
	const bool notInSSL = false;
#endif // USE_OPENSSL

	bool must_close = false;
	while(!mSendList.empty()) {
		char* sendptr = threadLocalSendBuf;
		size_t waitSendSize = 0;		// �ȴ�����

		for (auto it = mSendList.begin(); it != mSendList.end(); ++it) {
			auto& packet = *it;
			auto packetLeftBuf = (char*)(packet.data->c_str() + (packet.data->size() - packet.left)); // p + offset
			const auto packetLeftLen = packet.left;		// ʣ��buf
			if ((waitSendSize + packetLeftLen) > SENDBUF_SIZE) {
				if (it == mSendList.begin()) { // ��һ��
					sendptr = packetLeftBuf;
					waitSendSize = packetLeftLen;
				}
				break;	// ����sendbuf_size����
			}

			// ������threadLocalSendBuf,��waitSendSize��
			memcpy(sendptr + waitSendSize, packetLeftBuf, packetLeftLen);
			waitSendSize += packetLeftLen;
		}

		if (waitSendSize == 0) {	// ����sendlist�ĵ�һ��
			break;
		}

		int sendLen = 0;
#ifdef USE_OPENSSL
		if (mSSL != nullptr) {
				send_retlen = SSL_write(mSSL, sendptr, wait_send_size);
		} else {
				send_retlen = ::send(mSocket->getFD(), sendptr, wait_send_size, 0);
		}
#else
		sendLen = ::send(mSocket->getFD(), sendptr, static_cast<int>(waitSendSize), 0);

		if (sendLen <= 0) {		// ������
#ifdef USE_OPENSSL
		if ((mSSL != nullptr && SSL_get_error(mSSL, send_retlen) == SSL_ERROR_WANT_WRITE) ||
			(sErrno == S_EWOULDBLOCK)) {
			mCanWrite = false;
			must_close = !checkWrite();
		} else {
			must_close = true;
		}
#else
			if (sErrno == S_EWOULDBLOCK) {		// ��������
				mCanWrite = false;
				must_close = !checkWrite();
			} else {
				must_close = true;
			}
#endif
			break;
		}
#endif // USE_OPENSSL

		auto tmpLen = static_cast<size_t>(sendLen);		// �����ֽ���
		for (auto it = mSendList.begin(); it != mSendList.end();) {		// ���μ��ÿ�����Ƿ������,�����ɾ��
			auto& packet = *it;
			if (packet.left > tmpLen) {		// ��һ����δ������
				packet.left -= tmpLen;
				break;
			}

			tmpLen -= packet.left;		// ��һ�����������
			if (packet.mCompleteCallback != nullptr) {
				(packet.mCompleteCallback)();	// excut callback
			}
			it = mSendList.erase(it);
		}

		// δʹ��openssl notInSSL=false
		if (notInSSL && static_cast<size_t>(sendLen) != waitSendSize) {
			mCanWrite = false;
			must_close = !checkWrite();
			break;
		}
	}

	if (must_close) {
		procCloseInLoop();
	}
}

void DataSocket::quickFlush()
{
#ifdef PLATFORM_LINUX
#ifndef MAX_IOVEC
#define  MAX_IOVEC 1024
#endif

	struct iovec iov[MAX_IOVEC];
	bool must_close = false;

	while (!mSendList.empty()) {
		int num = 0;
		size_t ready_send_len = 0;
		for (PACKET_LIST_TYPE::iterator it = mSendList.begin(); it != mSendList.end();) {
			pending_packet& b = *it;
			iov[num].iov_base = (void*)(b.data->c_str() + (b.data->size() - b.left));
			iov[num].iov_len = b.left;
			ready_send_len += b.left;

			++it;
			num++;
			if (num >= MAX_IOVEC) {
				break;
			}
}

		if (num == 0) {
			break;
		}

		const int send_len = writev(mSocket->getFD(), iov, num);
		if (send_len <= 0) {
			if (sErrno == S_EWOULDBLOCK) {
				mCanWrite = false;
				must_close = !checkWrite();
			} else {
				must_close = true;
			}
			break;
		}

		auto tmp_len = static_cast<size_t>(send_len);
		for (PACKET_LIST_TYPE::iterator it = mSendList.begin(); it != mSendList.end();) {
			pending_packet& b = *it;
			if (b.left > tmp_len) {
				b.left -= tmp_len;
				break;
			}

			tmp_len -= b.left;
			if (b.mCompleteCallback != nullptr) {
				b.mCompleteCallback();
			}
			it = mSendList.erase(it);
		}

		if (static_cast<size_t>(send_len) != ready_send_len) {
			mCanWrite = false;
			must_close = !checkWrite();
			break;
		}
	}

	if (must_close) {
		procCloseInLoop();
	}
#endif
}

#ifdef PLATFORM_LINUX
void    DataSocket::removeCheckWrite()
{
	if (mSocket != nullptr) {
		struct epoll_event ev = {0, { 0 }};
		ev.events = EPOLLET | EPOLLIN | EPOLLRDHUP;
		ev.data.ptr = (Channel*)(this);
		epoll_ctl(mEventLoop->getEpollHandle(), EPOLL_CTL_MOD, mSocket->getFD(), &ev);
	}
}
#endif

DataSocket::PTR DataSocket::Create(TcpSocket::PTR socket, size_t maxRecvBufferSize, ENTER_CALLBACK enterCallback, EventLoop::PTR eventLoop)
{
	struct make_shared_ptr_enabler : public DataSocket
	{
		make_shared_ptr_enabler(TcpSocket::PTR socket, size_t maxRecvBufferSize, ENTER_CALLBACK enterCallback, EventLoop::PTR eventLoop)
			: DataSocket(std::move(socket), maxRecvBufferSize, enterCallback, eventLoop)
		{
		}
	};
	return std::make_shared<make_shared_ptr_enabler>(std::move(socket), maxRecvBufferSize, enterCallback, eventLoop);
}

bool DataSocket::onEnterEventLoop()
{
	if (!mEventLoop->isInLoopThread()) {
		assert(false);
		return false;
	}

	// ���÷�����,�󶨵���ɶ˿�
	if (!base::SocketNonBlock(mSocket->getFD()) || !mEventLoop->linkChannel(mSocket->getFD(), this)) {
		closeSocket();
		return false;
	}

	const auto findRet = mEventLoop->getDataSocketPtr(mSocket->getFD());
	assert(findRet == nullptr);

#ifdef USE_OPENSSL
	if (mSSL != nullptr) {
		mEventLoop->addDataSocket(mSocket->getFD(), shared_from_this());
		processSSLHandshake();
		return true;
	}
#endif
	if (!checkRead()) {
		closeSocket();
		return false;
	}

	mEventLoop->addDataSocket(mSocket->getFD(), shared_from_this());
	causeEnterCallback();

	return true;
}
const EventLoop::PTR & DataSocket::getEventLoop() const
{
	return mEventLoop;
}

void DataSocket::send(const char * buffer, size_t len, const PACKED_SENDED_CALLBACK & callback)
{
	send(makePacket(buffer, len), callback);
}

void DataSocket::send(const PACKET_PTR & packet, const PACKED_SENDED_CALLBACK & callback)
{
	auto packetCapture = packet;
	auto callbackCapture = callback;
	auto sharedThis = shared_from_this();

	mEventLoop->pushAsyncProc([sharedThis, packetCapture, callbackCapture](){  // async proc
		const auto len = packetCapture->size();
		if (sharedThis->mSocket != nullptr) {
			sharedThis->mSendList.push_back({std::move(packetCapture), len, std::move(callbackCapture)});
			sharedThis->runAfterFlush();	// pushafterloopproc
		}
	});
}

void DataSocket::sendInLoop(const PACKET_PTR & packet, const PACKED_SENDED_CALLBACK & callback)
{
	// ��loop�߳���
	assert(mEventLoop->isInLoopThread());
	if (mEventLoop->isInLoopThread() && mSocket != nullptr) {
		const auto len = packet->size();
		mSendList.push_back({packet, len, callback});
		runAfterFlush();
	}
}

void DataSocket::setDataCallback(DATA_CALLBACK cb)
{
	mDataCallback = std::move(cb);
}

void DataSocket::setDisconnectCallback(DISCONNECT_CALLBACK cb)
{
	mDisconnectCallback = std::move(cb);
}

void DataSocket::setHeardBeat(std::chrono::nanoseconds checkTime)
{
	if (!mEventLoop->isInLoopThread()) {	// ȷ����loop�߳���
		assert(false);
		return;
	}

	if (mTimer.lock() != nullptr) {
		mTimer.lock()->cancel();	// ȡ��timer
		mTimer.reset();
	}

	mCheckTime = checkTime;
	StartPingCheckTimer();
}

void DataSocket::postDisconnect()
{
	auto sharedThis(shared_from_this());
	mEventLoop->pushAsyncProc([sharedThis](){
		sharedThis->procCloseInLoop();
	});
}

void DataSocket::postShutdown()
{
	auto self(shared_from_this());
	mEventLoop->pushAsyncProc([self](){
		if (self->mSocket != nullptr) {
			self->mEventLoop->pushAfterLoopProc([self](){
				self->procShutdownInLoop();		// datasocket ִ��shutdowninloop
			});
		}
	});
}

void DataSocket::setUD(std::any value)
{
	mUD = std::move(value);
}

const std::any & DataSocket::getUD() const
{
	return mUD;
}

const std::string & DataSocket::getIP() const
{
	return mIP;
}

#ifdef USE_OPENSSL
bool DataSocket::initAcceptSSL(SSL_CTX* ctx)
{
	if (mSSL != nullptr) {
		return false;
	}

	mSSL = SSL_new(ctx);
	if (SSL_set_fd(mSSL, mSocket->getFD()) != 1) {
		ERR_print_errors_fp(stdout);
		::fflush(stdout);
		return false;
	}

	return true;
}

bool DataSocket::initConnectSSL()
{
	if (mSSLCtx != nullptr) {
		return false;
	}

	mSSLCtx = SSL_CTX_new(SSLv23_client_method());
	mSSL = SSL_new(mSSLCtx);

	if (SSL_set_fd(mSSL, mSocket->getFD()) != 1) {
		ERR_print_errors_fp(stdout);
		::fflush(stdout);
		return false;
	}

	return true;
}

bool DataSocket::processSSLHandshake()
{
	if (mIsHandsharked) {
		return true;
	}

	bool mustClose = false;
	int ret = 0;

	if (mSSLCtx != nullptr) {
		ret = SSL_connect(mSSL);
	} else {
		ret = SSL_accept(mSSL);
	}

	if (ret == 1) {
		mIsHandsharked = true;
		if (checkRead()) {
			causeEnterCallback();
		} else {
			mustClose = true;
		}
	} else if (ret == 0) {
		mustClose = true;
	} else if (ret < 0) {
		int err = SSL_get_error(mSSL, ret);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			if (!checkRead()) {
				mustClose = true;
			}
		} else {
			mustClose = true;
		}
	}

	if (mustClose) {
		causeEnterCallback();
		procCloseInLoop();
		return false;
	}
	return true;
}
#endif

void DataSocket::closeSocket()
{
	if (mSocket != nullptr) {
		mCanWrite = false;
		mSocket = nullptr;
	}
}

void DataSocket::procCloseInLoop()
{
	if (nullptr == mSocket) {
		return;
	}

#ifdef PLATFORM_WINDOWS
	if (mPostRecvCheck || mPostSendCheck) {
		closeSocket();		// ����˶�д
	} else {
		onClose();
	}
#else
	onClose();
#endif // !PLATFORM_WINDOWS
}

void DataSocket::procShutdownInLoop()
{
	if (mSocket != nullptr) {
#ifdef PLATFORM_WINDOWS
		shutdown(mSocket->getFD(), SD_SEND);		// ������д
#else
		shutdown(mSocket->getFD(), SHUT_WR);
#endif
		mCanWrite = false;
	}
}

void DataSocket::runAfterFlush()
{
	// ����postflush, sendlist��Ϊ��,
	if (!mIsPostFlush && !mSendList.empty() && mSocket != nullptr) {
		auto sharedThis = shared_from_this();
		mEventLoop->pushAfterLoopProc([sharedThis]() {	// ����asyncproc ��
			sharedThis->mIsPostFlush = false;
			sharedThis->flush();
		});
	}
	
}

void DataSocket::causeEnterCallback()
{
	assert(mEventLoop->isInLoopThread());
	if (mEventLoop->isInLoopThread()) {
		if (mEnterCallback != nullptr) {
			mEnterCallback(shared_from_this());
			mEnterCallback = nullptr;
		}
	}
}

}


