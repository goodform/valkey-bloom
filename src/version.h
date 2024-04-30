#ifndef VALKEYBLOOM_VERSION_H_
// This is where the modules build/version is declared.
// If declared with -D in compile time, this file is ignored


#ifndef VALKEYBLOOM_VERSION_MAJOR
#define VALKEYBLOOM_VERSION_MAJOR 1
#endif

#ifndef VALKEYBLOOM_VERSION_MINOR
#define VALKEYBLOOM_VERSION_MINOR 1
#endif

#ifndef VALKEYBLOOM_VERSION_PATCH
#define VALKEYBLOOM_VERSION_PATCH 0

#endif

#define VALKEYBLOOM_MODULE_VERSION \
  (VALKEYBLOOM_VERSION_MAJOR * 10000 + VALKEYBLOOM_VERSION_MINOR * 100 + VALKEYBLOOM_VERSION_PATCH)

#endif
