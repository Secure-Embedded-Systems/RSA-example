#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

static uint8_t privkey[] = 
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAojDGyuzNRtqWDS3no8PPA0LFCme4V8qnpKaJnHjp/YxMEcny\n"
"W3eWPBTtL0WUvSRHBY7PgiVTKWKN/4zuRq77XnLxZQuRGYQeLcpLmsyZPArnlfym\n"
"jZRsXPsnPscmbKt5SAxCrFKXKIwZ76rR7he/2OsxQ7O6yfIm3JQQRt1h+PjCvPoq\n"
"JmvqhbMDH/0bTeNEdGPQPEx8+Xohhkb6bYivH8Jcm1FkZTVDfMtZsmismghr7ufB\n"
"gOLrc9NnFO7r9G8MtV+mtqWV8Urm7KkN4fs/e9i8XlHcd7qalSlEtDl0+md6xwV0\n"
"ZFvJQ2jlQEnZ94CEgAwYlpbsGlis+cfjdIf+wQIDAQABAoIBAFRnwey1E5c+BjzR\n"
"mOz25/Kwes6Rb7PweRIMwSy3GD6lFqljSUckkwCte0nQkjlkebmAuqjmN8Mf0Pof\n"
"I5mRUquyccG+JUL8KKB32KS0uUIwAplhpGOlzEcPRTs8dNi03CcMil4XlSa60nyR\n"
"jzKzFVoT+81Z6WlTJbpBK79VUrk4GCNPrvwU3r+H68zOQG0CSia5eoWSOEVuFlSw\n"
"01ixNbQRgCKZQQB72FQAtxBNIiPuWNg1nc+a7GMMKMmzzHr2xNUyv6byiQ0ADW6v\n"
"uOZbuNJ6gy6xltswGjR3mUcmGA9JoLwKTHLKD9qDzAE40RYU/G3I3o1PsbzdYnIr\n"
"hPnoLwkCgYEA0b3vBcpyIld1+BYPB1Q0b5uFbTXbegGvR8jU82ZGWs/uKUpO/wmq\n"
"A3P2Q7Bm+91Zsz0hiQ56k2N2tsb5H/tOcOwBSkzbViJ4w9IroFZydQpv5mZXSELh\n"
"b0wSnet4L99TxsJiA55S6JmawrgRCBGhOsTQA0bKNGFioN1CkcVrjhsCgYEAxfYV\n"
"KvdhmU9hRauYFHYVCiHYTC8ae8W1p8YwUc6N9PnUvUazYCpX257HlQgs0QzIcj0k\n"
"dz9/DqfE6xuPdVzyrFwwdn3MthN6QOWUNEnh0XeVnoUtFS8Tld3YFVO9sCGQg1JV\n"
"OWasqz8G/xxxycjiKp7ls5jcgJ/K5JaNwyJZhFMCgYBacgIxyBQhtP99JN4ENg6K\n"
"llEaQCBN444XcYZLE66BGKtGCPI5zowPAyGOHPK75773qQPeG21GQ5z8wp7JaNBx\n"
"p4QC61OmOCVFpEsF0GF5ETAh9b3rvlOCcBaTHOhuFGsHCenET7DG9v4iu8c0aI3T\n"
"Tu24i/1ESz6Byggb3js8QwKBgBfTlpilTcn2E+8eyB8uVznw+Oeyg62CDmszH325\n"
"LrzdlQ1zBQP+FLUKV1tIsJw4vaeCVHFF4zUQXFMv7gRiO5MjRXH9kjYYAg7tkvj4\n"
"K4Xartd1kAeMsv7GxMtMWPhqEcq8jiVqhj3WSDFMayWuWAppNZx4OZIBqZn5xPZH\n"
"nB6hAoGBAK70lFDgWH7tm6kmmSSSDk9jk4CHiXgWogVGog0+RAtKf4JaFU6Tz5UY\n"
"ejqo/sXVm7GCAKtpQ6iK79ZMmFOVG4fGx3WdrjAmCLspiO3FeJ2dR0hoc/OkbDv/\n"
"QOtjDKCvW8b3bLUD369Yh9GVCur5eJ6sjZga4D7jaSEgON3ENIkE\n"
"-----END RSA PRIVATE KEY-----\n";

static uint8_t ct[] = 
"\x17\x04\x58\xb8\x10\x8c\x0d\xd6\x98\xf8\x84\xd2\xe1\x29\xf9\x4a\xa1\x38\xa3\xf7\xfd\x57\x13\x01\x57\x55\xd5\xe9\x57\xdf\x8b\x49\x15\x5f\x2e\x79\xd3\xd8\x08\x65\x60\xbd\x36\xa7\xc9\x23\x6d\x0d\xb9\x0b\xe7\x34\x8d\x3b\x96\x13\x0c\x95\x8e\x21\x5e\x5b\x89\x56\x97\x56\xe8\xa2\x72\xd7\x8e\xbc\xd6\x1d\x77\xa1\x7f\x3c\x1f\x1b\xfe\xf1\xe0\x35\x59\xe2\xcc\xbd\x54\x7c\xfb\x2e\x41\x7d\xd9\x1c\xff\x34\xd5\xa7\x40\x52\xa0\x41\x05\xd1\x01\x8b\x10\x24\x4e\x5f\x55\x47\xf9\x2a\x87\x56\x57\x86\x5f\xfb\xd0\xc1\x75\x62\xbf\x4d\xbd\x46\x13\xb2\x0e\x6b\x0f\x96\x0a\xf1\x0d\x18\xc0\xb8\xef\x3a\x61\x31\xff\x24\x15\xdd\x71\x56\xe1\x83\xf6\x86\x2a\x12\x8b\x51\x6c\x10\xad\x96\xd9\x36\xb9\xdc\xa1\xa6\x6e\x42\x73\x17\xa5\xad\xaf\x1f\x9e\x89\xcf\xd7\x23\x96\xaa\xd7\xc5\x12\xdb\x05\x56\xad\xcf\xe5\x56\x2a\xe7\x4f\x42\x11\xc2\xed\xd6\x29\x3d\xa3\x3f\x2c\xab\xad\x30\xdd\xed\x0f\xfc\x2c\x6b\x28\x50\x33\x15\x83\x7f\xb6\x6c\x26\xb8\xd8\x77\xeb\xc5\x53\xe1\x5b\xd2\x44\xc0\x1e\xcc\x92\xcb\xf6\x9e\xcd\xb1\xc4\x58\xd8\x3c\x4b\x5f\x9b\xe4\x20\xd3\x5a";

uint8_t result[1024*1024];

int main()
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );


    int ret;

    if ((ret=mbedtls_pk_parse_key(&pk, privkey, sizeof(privkey), NULL, 0)) != 0)
    {
        uint8_t buffer[100];
        mbedtls_strerror(ret,buffer, 100) ;
        printf( "parse key failed\n  ! mbedtls_pk_decrypt returned -0x%04x %s\n", -ret,buffer );
        return -1;
    }

    size_t olen = 0;
    /*printf("sizeof(ct):%d\n", pk.pk_info);*/

    if( ( ret = mbedtls_pk_decrypt( &pk, ct, sizeof(ct)-1, result, &olen, sizeof(result),
                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        uint8_t buffer[100];
        mbedtls_strerror(ret,buffer, 100) ;
        printf( "decrypt failed\n  ! mbedtls_pk_decrypt returned -0x%04x %s\n", -ret,buffer );

    }
    else
    {
        printf("result: %s\n", result); // should be "hello world"
    }

    return 0;
}
