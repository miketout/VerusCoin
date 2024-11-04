#include <cstdlib>
#include "uint256.h"
#include "crypto/verus_clhash.h"

#if defined(__APPLE__) || defined(_WIN32)
// attempt to workaround horrible mingw/gcc destructor bug on Windows and Mac, which passes garbage in the this pointer
// we use the opportunity of control here to clean up all of our tls variables. we could keep a list, but this is a safe,
// functional hack
thread_specific_ptr::~thread_specific_ptr() {
    if (verusclhasher_key.ptr)
    {
        verusclhasher_key.reset();
    }
    if (verusclhasher_descr.ptr)
    {
        verusclhasher_descr.reset();
    }
}
#endif // defined(__APPLE__) || defined(_WIN32)

thread_local thread_specific_ptr verusclhasher_key;
thread_local thread_specific_ptr verusclhasher_descr;
