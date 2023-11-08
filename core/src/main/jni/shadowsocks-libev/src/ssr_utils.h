#ifndef SAMA_SERVICE_SSR_UTILS_H__
#define SAMA_SERVICE_SSR_UTILS_H__

#if defined(__CYGWIN__)
#ifndef CONNECT_IN_PROGRESS
#define CONNECT_IN_PROGRESS 119
#endif
#endif

#ifndef CONNECT_IN_PROGRESS
#define CONNECT_IN_PROGRESS 115
#endif

//#include <netinet/tcp.h>

#ifndef MAX_REQUEST_TIMEOUT
#define MAX_REQUEST_TIMEOUT 30
#endif

#endif