#include <ft_openssl.h>
#include <ft_openssl_utils.h>

// clang-format off
/*

c         = iteration count
DK        = derived key
dkLen     = derived key length in octet 
l         = len in block of derived key
IV        = initialization vector
K         = encryption key
Hash      = underlying hash function
PRF       = underlying pseudorandom function
hLen      = length in octet of pseudorandom function output (PRF)
KDF       = key derivation function 
P         = password
S         = salt
PS        = padding string
psLen     = length in octet of padding string

DK = KDF (P, S)


TO derive key in decryption, we need to know :
- S
- c
- Hash 

dkLen = 8
S = PRF(dkLen)
c = 1000
P = input



ADD SALT TO PASSWORD

FOR X ITERATION:
    HASH COMBINATION WITH ANY HASH FUNCTION

*/

// clang-format on