#ifndef _CURRENTTHREAD_H_
#define _CURRENTTHREAD_H_


#include <winsock2.h>
#include <Windows.h>


namespace net {
	namespace CurrentThread {

		typedef DWORD THREAD_ID_TYPE;
		extern thread_local THREAD_ID_TYPE cachedTID;

		THREAD_ID_TYPE& tid();
	}
}


#endif // !_CURRENTTHREAD_H_



