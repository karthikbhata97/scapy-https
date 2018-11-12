from __future__ import print_function
from scapy.layers.ssl_tls import *
import scapy.layers.ssl_tls as scapy_ssl
import argparse
import sys
import helpers
import  Cryptodome


def tls_client_mutual_auth(host, cert, key, version, ciphers, extensions, request):
    with open(cert, "rb") as f:
        client_cert = f.read()
    certificate = TLSCertificate(data=client_cert)

    tls_version = version

    with TLSSocket(socket.socket(), client=True) as tls_socket:
        tls_socket.connect(host)
        tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.abspath(key))

        client_hello = TLSRecord(version=tls_version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() /
                                                 TLSClientHello(version=tls_version,
                                                                cipher_suites=ciphers,
                                                                extensions=extensions)])
        
        server_hello = tls_socket.do_round_trip(client_hello)
        # server_hello.show()

        client_cert = TLSRecord(version=tls_version) / \
                      TLSHandshakes(handshakes=[TLSHandshake() / TLSCertificateList() /
                                                TLS10Certificate(certificates=certificate)])
        client_key_exchange = TLSRecord(version=tls_version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                        tls_socket.tls_ctx.get_client_kex_data()])
        p = TLS.from_records([client_cert, client_key_exchange])
        tls_socket.do_round_trip(p, recv=False)

        sig = tls_socket.tls_ctx.compute_client_cert_verify(digest=Cryptodome.Hash.SHA256)

        client_cert_verify = TLSRecord(version=tls_version) / \
                             TLSHandshakes(handshakes=[TLSHandshake() /
                                                       TLSCertificateVerify(alg=TLSSignatureScheme.RSA_PKCS1_SHA256,
                                                                            sig=sig)])
        tls_socket.do_round_trip(client_cert_verify, recv=False)

        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        tls_socket.do_round_trip(client_ccs, recv=False)
        server_finished = tls_socket.do_round_trip(TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
        server_finished.show()

        resp = tls_socket.do_round_trip(TLSPlaintext(data=request))
        tls_socket.close()
        
        return resp


def run(server, cert, key, tls_version, ciphers, extensions, req, resp_file):
    resp = tls_client_mutual_auth((host, port), cert, key, tls_version, ciphers, extensions, req)

    if not resp:
        sys.exit(-1)
    
    if not resp.fields:
        resp.show()
    else:
        for record in resp.fields['records']:
            if TLSPlaintext in record:
                data = record[TLSPlaintext].data
                with open(resp_file, 'a+') as f:
                    f.write(data)
    

def versions_action():
    class customAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            print_versions()
            setattr(args, self.dest, values)
            parser.exit()
    return customAction

def extensions_action():
    class customAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            print_extensions()
            setattr(args, self.dest, values)
            parser.exit()
    return customAction

def ciphersuites_action():
    class customAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            print_ciphersuites()
            setattr(args, self.dest, values)
            parser.exit()
    return customAction


def all_action():
    class customAction(argparse.Action):
        def __call__(self, parser, args, values, option_string=None):
            print_versions()
            print_extensions()
            print_ciphersuites()
            setattr(args, self.dest, values)
            parser.exit()
    return customAction


def print_versions():
    print('Versions')
    for i in range(len(helpers.versions)):
        print (str(i) + ': ' + helpers.versions[i])

def print_extensions():
    print('Extensions')
    for i in range(len(helpers.extensions)):
        print (str(i) + ': ' + helpers.extensions[i])

def print_ciphersuites():
    print('Ciphersuites')
    for i in range(len(helpers.ciphersuites)):
        print (str(i) + ': ' + helpers.ciphersuites[i])



if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('host', type=str, nargs=1)
    parser.add_argument('port', type=int, nargs=1)

    parser.add_argument('-r', '--request', type=str, nargs='?', help='Filename contaiting request header')
    parser.add_argument('-o', '--response', type=str, nargs=1, help='Filename to write response')
    parser.add_argument('-u', '--url', type=str, nargs='?', help='GET request url')

    parser.add_argument('--list_versions', action=versions_action(), nargs=0)
    parser.add_argument('--list_extensions', action=extensions_action(), nargs=0)
    parser.add_argument('--list_ciphersuites', action=ciphersuites_action(), nargs=0)
    parser.add_argument('-a', '--list_all', action=all_action(), nargs=0)

    parser.add_argument('-v', '--version', type=int, nargs='*', help='Version number to be used. \
                        Use --list_versions options to find the corresponding number')

    parser.add_argument('-c', '--ciphersuites', type=int, nargs='*', help='Ciphersuite to be used. \
                        Use --list_ciphersuites options to find the corresponding number')

    parser.add_argument('-e', '--extensions', type=int, nargs='*', help='Extensions to be used. \
                        Use --list_extensions options to find the corresponding number')

    parser.add_argument('--version_name', type=str, nargs='?', help='Version number to be used.')
    parser.add_argument('--ciphersuites_name', type=str, nargs='*', help='Ciphersuite to be used.')
    parser.add_argument('--extensions_name', type=str, nargs='*', help='Extensions to be used.')

    parser.add_argument('--cipher_type', type=str, nargs=1, help='Type of ciphersuites to be used.')
    
    parser.add_argument('-s', '--cert', type=str, nargs=1, help='Client certificate')
    parser.add_argument('-k', '--key', type=str, nargs='?', help='Client Key')


    args = parser.parse_args()

    
    cert = args.cert[0]

    if args.key:
        key = args.key
    else:
        key = cert

    if args.version:
        tls_version = helpers.get_version(args.version[0])
    elif args.version_name:
        tls_version = getattr(TLSVersion, args.version_name)
    else:
        tls_version = getattr(TLSVersion, 'TLS_1_2')

    extensions = []
    if args.extensions:
        for e in args.extensions:
            tmp_ext = helpers.get_ext(e)
            extensions.append(TLSExtension()/tmp_ext())
    elif args.extensions_name:
        for name in args.extensions_name:
            tmp_ext = getattr(scapy_ssl, name)
            extensions.append(TLSExtension()/tmp_ext())
            
    ciphers = []
    if args.cipher_type:
        ciphers = helpers.get_all_ciphers(args.cipher_type[0])
        
        if len(ciphers) == 0:
            print('No such ciphersuites')
            sys.exit(0)
    elif args.ciphersuites:
        for c in args.ciphersuites:
            ciphers.append(helpers.get_cs(c))
    elif args.ciphersuites_name:
        for c in args.ciphersuites_name:
            cs = getattr(TLSCipherSuite, c)
            ciphers.append(cs)
    else:
        ciphers.append(helpers.get_cs(179))
        tmp_ext = helpers.get_ext(4)
        extensions.append(TLSExtension()/tmp_ext())
        tmp_ext = helpers.get_ext(18)
        extensions.append(TLSExtension()/tmp_ext())


    host = args.host[0]
    port = args.port[0]

    resp_file = args.response[0]

    if args.request:
        req = args.request
        with open(req, 'r') as f:
            req = f.read()

        req = req.replace('\r', '\r\n')
    elif args.url:
        url = args.url
        print(url)
        req = 'GET' + ' /' + url.split('://')[1].split('/', 1)[1] + ' HTTP/1.1\r\n' + 'HOST: ' + host + '\r\n\r\n'
    else:
        print('Give one of request file or URL')
        sys.exit(-1)

    if req[-4:] != '\r\n\r\n':
        req += '\r\n'

    if req[-4:] != '\r\n\r\n':
        req += '\r\n'

    print('Request:\n', repr(req))

    with open(resp_file, 'w') as f:
        f.write("")

    run((host, port), cert, key, tls_version, ciphers, extensions, req, resp_file)
