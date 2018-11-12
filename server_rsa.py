from __future__ import print_function
import os
from scapy.layers.ssl_tls import *
import argparse
import helpers
import sys


def handle_client(client_socket, certificates, cipher, response_file):
    try:
        r = client_socket.recvall()
        version = r[TLSHandshakes].handshakes[0][TLSClientHello].version
        server_hello = TLSRecord(version=version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() / TLSServerHello(version=version, cipher_suite=cipher),
                                                 TLSHandshake() / TLSCertificateList() /TLS10Certificate(certificates=certificates),
                                                 TLSHandshake(type=TLSHandshakeType.SERVER_HELLO_DONE)])
        r = client_socket.do_round_trip(server_hello)
        r.show()

        client_socket.do_round_trip(TLSRecord(version=version) /
                                    TLSChangeCipherSpec(), recv=False)
        r = client_socket.do_round_trip(TLSHandshakes(handshakes=[TLSHandshake() /
                                                                  TLSFinished(data=client_socket.tls_ctx.get_verify_data())]))

        r.show()

        with open(response_file, 'r') as f:
            app_data = f.read()

        client_socket.do_round_trip(TLSPlaintext(data=app_data), recv=False)
        client_socket.do_round_trip(TLSAlert(), recv=False)
    except TLSProtocolError as tpe:
        print("Got TLS error: %s" % tpe, file=sys.stderr)
        tpe.response.show()
    finally:
        print(client_socket.tls_ctx)

def serve(host, server_cert, server_key, cipher, response_file):
    with open(server_cert, "rb") as f:
            cert = f.read()
    certificates = TLSCertificate(data=cert)

    with TLSSocket(client=False) as tls_socket:
        tls_socket.tls_ctx.server_ctx.load_rsa_keys_from_file(os.path.abspath(server_key))

        try:
            tls_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            tls_socket.bind(host)
        except socket.error as se:
            print("Failed to bind server: %s" % (host,), file=sys.stderr)

        tls_socket.listen(1)
        client_socket, _ = tls_socket.accept()

        handle_client(client_socket, certificates, cipher, response_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('host', type=str, nargs=1)
    parser.add_argument('port', type=int, nargs=1)

    parser.add_argument('-s', '--cert', type=str, nargs=1, help='Server certificate')
    parser.add_argument('-k', '--key', type=str, nargs='?', help='Server Key')
    parser.add_argument('-r', '--response', type=str, nargs=1, help='Response file')

    parser.add_argument('-c', '--ciphersuite', type=str, nargs=1, help='Ciphersuite to be used.')

    args = parser.parse_args()

    host = args.host[0]
    port = args.port[0]

    response = args.response[0]

    server_cert = args.cert[0]

    if args.key:
        server_key = args.key
    else:
        server_key = server_cert

    cs = args.ciphersuite[0]
    ciphersuite = getattr(TLSCipherSuite, cs, None)
    if not ciphersuite:
        print('Ciphersuite not found')
        sys.exit(0)

    # Accepts single connection only. socket.accept is failing on second time for some reason.
    serve((host, port), server_cert, server_key, ciphersuite, response)
