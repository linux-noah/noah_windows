#ifndef NOAH_MM_HPP
#define NOAH_MM_HPP

// TODO: Merge this file into mm.h after migrating all source files to C++

#include <boost/interprocess/managed_external_buffer.hpp>

extern boost::interprocess::managed_external_buffer *vkern_shm;

void init_vkern_shm();


#endif
