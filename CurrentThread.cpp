#include "CurrentThread.h"


namespace net {
	namespace CurrentThread {
		thread_local THREAD_ID_TYPE cachedTID = 0;
		THREAD_ID_TYPE & tid()
		{
			if (0 == cachedTID) {
				cachedTID = GetCurrentThreadId();
			}

			return cachedTID;
		}
	}
}


