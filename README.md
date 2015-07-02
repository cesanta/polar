#PolarSSL &lt;-> OpenSSL compatibility layer

This library is designed to provide SSL support for Mongoose Web Server via PolarSSL.
It gives an opportunity to use PolarSSL via OpenSSL-like API.

The library contains implementation of the following OpenSSL API functions:

```C
int SSL_read(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_get_error(const SSL *ssl, int ret);
int SSL_connect(SSL *ssl);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_accept(SSL *ssl);
int SSL_library_init();
SSL_METHOD* SSLv23_client_method();
SSL_METHOD* SSLv23_server_method();
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);

void SSL_CTX_free(SSL_CTX *ctx);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void* reserved);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
SSL_CTX *SSL_CTX_new(SSL_METHOD* ssl_method);
```

Basically this library is intended for Mongoose Web Server, and it implements restricted set of API with additional limitations pointer below.
- `SSL_CTX_set_verify` function accepts `SSL_VERIFY_PEER` mode only;
- `SSL_CTX_set_mode` works for `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER` mode only;
- `SSL_CTX_use_certificate_file`, `SSL_CTX_use_PrivateKey_file`, `SSL_CTX_use_certificate_chain_file` assumes PEM format only;
- `SSL_CTX_load_verify_locations` function doesn’t support `CApath` parameter, and imports certificate provided in CAfile parameter immediately, but not on demand (unlike OpenSSL).

The library was developed and tested with PolarSSL (currently mbedtls) version 1.3.10, which could be downloaded here: https://tls.mbed.org/download/start/mbedtls-1.3.10-gpl.tgz.

PolasSSL should be located in /usr/bin in order to compile example «out-of-box». Otherwise changes in makefile could be required. See polar/examples/web_server/Makefile for details.

#Licensing

The library is released under commercial and GNU GPL v.2 open source licenses. The GPLv2 open source License does not generally permit incorporating this software into non-open source programs. For those customers who do not wish to comply with the GPLv2 open source license requirements, Cesanta Software offers a full, royalty-free commercial license and professional support without any of the GPL restrictions.

 
