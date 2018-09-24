# Scapy HTTPS
### requirements
- scapy-ssl_tls: https://github.com/tintinweb/scapy-ssl_tls

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
