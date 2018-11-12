from __future__ import print_function
from scapy.layers.ssl_tls import *
import argparse
import sys
import helpers


def tls_client(ip, request, tls_version, ciphers, extensions):
    resp = None
    with TLSSocket(client=True) as tls_socket:
        try:
            tls_socket.connect(ip)
            print("Connected to server: %s" % (ip,))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        else:
            try:
                server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
            else:
                resp = tls_socket.do_round_trip(TLSPlaintext(data=request))
                tls_socket.close()
    return resp

def run(server, req, tls_version, ciphers, extensions, resp_file):
    resp = tls_client((host, port), req, tls_version, ciphers, extensions)

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

    parser.add_argument('-v', '--version', type=int, nargs=1, help='Version number to be used. \
                        Use --list_versions options to find the corresponding number')

    parser.add_argument('-c', '--ciphersuites', type=int, nargs='+', help='Ciphersuite to be used. \
                        Use --list_ciphersuites options to find the corresponding number')

    parser.add_argument('-e', '--extensions', type=int, nargs='*', help='Extensions to be used. \
                        Use --list_extensions options to find the corresponding number')

    args = parser.parse_args()

    tls_version = helpers.get_version(args.version[0])
    extensions = []
    if args.extensions:
        for e in args.extensions:
            tmp_ext = helpers.get_ext(e)
            extensions.append(TLSExtension()/tmp_ext())

    ciphers = []
    for c in args.ciphersuites:
        ciphers.append(helpers.get_cs(c))

    host = args.host[0]
    port = args.port[0]

    resp_file = args.response[0]

    if args.request:
        req = args.request
        with open(req, 'r') as f:
            req = f.read()

        req = req.replace('\n', '\r\n')
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

    run((host, port), req, tls_version, ciphers, extensions, resp_file)