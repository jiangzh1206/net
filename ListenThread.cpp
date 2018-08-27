#include "ListenThread.h"

#include <iostream>

namespace net {
	
static net::TcpSocket::PTR runOnceListen(const std::shared_ptr<ListenSocket>& listenSocket)
{
	try {
		auto clientSocket = listenSocket->Accept();
		return clientSocket;
	} catch (const EintrError& e) {
		std::cerr << "accept eintr exception: " << e.what() << std::endl;		// 中断
	} catch (const AcceptError& e) {
		std::cerr << "accept exception: " << e.what() << std::endl;
	} catch (...) {
		std::cerr << "accept unkown exception: " << e.what() << std::endl;
	}

	return nullptr;
}


ListenThread::ListenThread() noexcept
	: mIsIPV6(false)
	, mPort(0)
	, mRunListen(std::make_shared<bool>(false))
{
}

ListenThread::~ListenThread() noexcept
{
	stopLissten();
}

ListenThread::PTR ListenThread::Create()
{
	struct make_shared_enabler : public ListenThread{
	};
	return std::make_shared<make_shared_enabler>();
}
void ListenThread::startListen(bool isIPV6, const std::string & IP, int port, ACCEPT_CALLBACK callback)
{
	std::lock_guard<std::mutex> lk(mListenThreadGuard);

	if (mListenThread != nullptr) {
		return;
	}

	if (callback == nullptr) {
		throw std::runtime_error("accept callback is nullptr.");
	}

	const sock fd = base::Listen(isIPV6, IP.c_str(), port, 512);		// 创建并监听
	if (fd == INVALID_SOCKET) {
		throw std::runtime_error(std::string("listen error of: ") + std::to_string(sErrno));
	}
	
	mIsIPV6 = isIPV6;
	mRunListen = std::make_shared<bool>(true);
	mIP = IP;
	mPort = port;

	auto listenSocket = std::make_shared<ListenSocket>(ListenSocket::Create(fd));
	auto isRunListen = mRunListen;

	mListenThread = std::make_shared<std::thread>([isRunListen, listenSocket, callback]() mutable { // mutable ?
		while (*isRunListen) {
			auto clientSocket = runOnceListen(listenSocket);
			if (clientSocket == nullptr) {
				continue;
			}
			if (*isRunListen) {
				callback(std::move(clientSocket));
			}
		}
	});
}

void ListenThread::stopLissten()
{
	std::lock_guard<std::mutex> lk(mListenThreadGuard);
	
	if (mListenThread == nullptr) {
		return;
	}

	*mRunListen = false;
	auto selfIP = mIP;
	if (selfIP == "0.0.0.0") {
		selfIP = "127.0.0.1";		// why?
	}

	SyncConnectSocket(selfIP, mPort, std::chrono::seconds(10));

	try {
		if (mListenThread->joinable()) {
			mListenThread->join();
		}
	} catch (...) {

	}
	mListenThread = nullptr;
}

}

