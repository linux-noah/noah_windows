#ifndef NOAH_CONST_H
#define NOAH_CONST_H

#include "cross_platform.h"

/*
 *  Constant conversion macros.
 */

#define DECL_LINUX_constant(const_name, val, ...) const_name = val,
#define DECL_ALIAS_constant(const_name, val)      const_name = val,

#define DECL_LINUX_strtable(const_name, val, ...) case val: return #const_name;
#define DECL_ALIAS_strtable(const_name, val)

#define DECL_LINUX(tag, const_name, val)  DECL_LINUX_ ## tag (LINUX_ ## const_name, val, const_name)
#define DECL_ALIAS(tag, const_name, val)  DECL_ALIAS_ ## tag (LINUX_ ## const_name, val)

#define DECLARE_CSTR_FUNC(const_id, const_list) \
  static inline char * linux_##const_id##_##str(int val) {\
    switch (val) { \
      const_list(strtable)\
    }\
    return "(No " #const_id " Matched)";\
  }

#define DECLARE_CENUM(const_id, const_list) \
  enum linux_##const_id { \
    const_list(constant)\
  };

#endif
