#ifndef CONFIG_H
#define CONFIG_H

#define WORD_SIZE sizeof(int)

#if !defined(X86) && !defined(X86_64)
#   if defined(__x86_64__) || defined(__x86_64)
#       define X86_64
#   elif defined(__i386__) || defined(__i386) || defined(_M_I86) || defined(_M_IX86)
#       define I386
#   else
#       error Unrecognized architecture!
#   endif
#endif

/* Static assertion trick */
enum { ASSERT_POINTER_FITS_IN_LONG_INT = 1/(!!(
        sizeof(long int) >= sizeof(void*)
)) };

typedef signed long int register_type;

#endif
