/* Host-only substitute: use Linux's OS random source, never test constants. */
#ifndef RNG_SHIM_h
#define RNG_SHIM_h
#define CRYPTO_RNG_h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/random.h>
/* The Arduino library supplies these macros itself on non-AVR hosts. */
#undef htole16
#undef le16toh
#undef htobe16
#undef be16toh
#undef htole32
#undef le32toh
#undef htobe32
#undef be32toh
#undef htole64
#undef le64toh
#undef htobe64
#undef be64toh
class RNGClass {
public:
    void rand(uint8_t *data, size_t len) {
        while (len) {
            ssize_t n = getrandom(data, len, 0);
            if (n < 0 && errno == EINTR) { continue; }
            if (n <= 0) { abort(); }
            data += n;
            len -= n;
        }
    }
};
extern RNGClass RNG;
#endif
