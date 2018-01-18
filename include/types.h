#ifndef NOAH_TYPES_H
#define NOAH_TYPES_H

#if defined(__unix__) || defined(TARGET_OS_MAC)
#include <unistd.h>
#elif defined(_WIN32)
#include <sys/types.h>
#endif

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/managed_external_buffer.hpp>
#include <boost/interprocess/offset_ptr.hpp>

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

typedef uint64_t gaddr_t;
typedef gaddr_t  gstr_t;

using boost::interprocess::offset_ptr;
namespace bip = boost::interprocess;

using extbuf = bip::managed_external_buffer;

template <typename T>
using extbuf_allocator_t = bip::allocator<T, extbuf::segment_manager>;
template <typename T>
using extbuf_deleter_t = bip::deleter<T, extbuf::segment_manager>;

template <typename K, typename V, typename Compare = std::less<K>>
using extbuf_map_t = bip::map<K, V, Compare, extbuf_allocator_t<std::pair<const K, V>>>;

using mutex_t = bip::interprocess_mutex;
template <typename T>
using shared_ptr = bip::shared_ptr<T, extbuf_allocator_t<offset_ptr<void>>, bip::deleter<T, extbuf::segment_manager>>;

#endif
