# Scapy HTTPS
### requirements
- scapy-ssl_tls: https://github.com/tintinweb/scapy-ssl_tls
- pycryptodome (Used only in client authentication script)

This will make use of the module [scapy-ssl_tls](https://github.com/tintinweb/scapy-ssl_tls).
This is a simple script `https_request.py` which will run a http query to the sever over TLS.
We can select
- TLS version
- Ciphersuites
- Extensions
for the connection.

This will take server IP, port as positional arguments. It also requires a request file containing http header with -r argument.(check `request.txt` file).
The response will be saved to the response file with -o argument.

The options for choosing version, ciphersuites and extensions is done using the index values which are in `help.txt` file or can be obtained using -a argument.

* Example
  ```
  python https_request.py localhost 443 -v 4 -c 179 -e 4 18 -r request.txt -o response.txt
  ```

* Help
```
usage: https_request.py [-h] [-r [REQUEST]] [-o RESPONSE] [-u [URL]]
                        [--list_versions] [--list_extensions]
                        [--list_ciphersuites] [-a] [-v VERSION]
                        [-c CIPHERSUITES [CIPHERSUITES ...]]
                        [-e [EXTENSIONS [EXTENSIONS ...]]]
                        host port

positional arguments:
  host
  port

optional arguments:
  -h, --help            show this help message and exit

  -r [REQUEST], --request [REQUEST]
                        Filename contaiting request header

  -o RESPONSE, --response RESPONSE
                        Filename to write response

  -u [URL], --url [URL]
                        GET request url

  --list_versions
  --list_extensions
  --list_ciphersuites
  -a, --list_all

  -v VERSION, --version VERSION
                        Version number to be used. Use --list_versions options
                        to find the corresponding number

  -c CIPHERSUITES [CIPHERSUITES ...], --ciphersuites CIPHERSUITES [CIPHERSUITES ...]
                        Ciphersuite to be used. Use --list_ciphersuites
                        options to find the corresponding number

  -e [EXTENSIONS [EXTENSIONS ...]], --extensions [EXTENSIONS [EXTENSIONS ...]]
                        Extensions to be used. Use --list_extensions options
                        to find the corresponding number
```

### HTTPS client with client authentication
This accepts client `Certificate` and `Key` to do client authentication.
* Help
  ```
  usage: https_request_with_client_auth.py [-h] [-r [REQUEST]] [-o RESPONSE]
                                         [-u [URL]] [--list_versions]         
                                         [--list_extensions]                
                                         [--list_ciphersuites] [-a]
                                         [-v [VERSION [VERSION ...]]]
                                         [-c [CIPHERSUITES [CIPHERSUITES ...]]]
                                         [-e [EXTENSIONS [EXTENSIONS ...]]]
                                         [--version_name [VERSION_NAME]]
                                         [--ciphersuites_name [CIPHERSUITES_NAME [CIPHERSUITES_NAME ...]]]
                                         [--extensions_name [EXTENSIONS_NAME [EXTENSIONS_NAME ...]]]
                                         [--cipher_type CIPHER_TYPE] [-s CERT]
                                         [-k [KEY]]     
                                         host port
  positional arguments:
  host
  port

    optional arguments:
    -h, --help            show this help message and exit
    -r [REQUEST], --request [REQUEST]
                            Filename contaiting request header
    -o RESPONSE, --response RESPONSE
                            Filename to write response
    -u [URL], --url [URL]
                            GET request url
    --list_versions
    --list_extensions
    --list_ciphersuites
    -a, --list_all
    -v [VERSION [VERSION ...]], --version [VERSION [VERSION ...]]
                            Version number to be used. Use --list_versions options
                            to find the corresponding number
    -c [CIPHERSUITES [CIPHERSUITES ...]], --ciphersuites [CIPHERSUITES [CIPHERSUITES ...]]
                            Ciphersuite to be used. Use --list_ciphersuites
                            options to find the corresponding number
    -e [EXTENSIONS [EXTENSIONS ...]], --extensions [EXTENSIONS [EXTENSIONS ...]]
                            Extensions to be used. Use --list_extensions options
                            to find the corresponding number
    --version_name [VERSION_NAME]
                            Version number to be used.
    --ciphersuites_name [CIPHERSUITES_NAME [CIPHERSUITES_NAME ...]]
                            Ciphersuite to be used.
    --extensions_name [EXTENSIONS_NAME [EXTENSIONS_NAME ...]]
                            Extensions to be used.
    --cipher_type CIPHER_TYPE
                            Type of ciphersuites to be used.
    -s CERT, --cert CERT  Client certificate
    -k [KEY], --key [KEY]
                            Client Key
  ```


### RSA Server
* Usage
  ```
    usage: server_rsa.py [-h] [-s CERT] [-k [KEY]] [-r RESPONSE] [-c CIPHERSUITE]
                        host port

    positional arguments:
    host
    port

    optional arguments:
    -h, --help            show this help message and exit
    -s CERT, --cert CERT  Server certificate
    -k [KEY], --key [KEY]
                            Server Key
    -r RESPONSE, --response RESPONSE
                            Response file
    -c CIPHERSUITE, --ciphersuite CIPHERSUITE
                            Ciphersuite to be used.
  ```

* Example
    ```
    python server_rsa.py 127.0.0.1 8443 -c RSA_WITH_AES_128_CBC_SHA -s keys/cert.der -k keys/key.pem -r README.md
    ```