"""Create the proper self-signed certificate and private key for *.xlink.cn Common Name (CN)."""

import os
from pathlib import Path
from typing import Union, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from datetime import datetime, timedelta


def generate_certs(
    key_out: Union[str, os.PathLike, None] = None,
    cert_out: Union[str, os.PathLike] = None,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed certificate and private key using *.xlink.cn for Common Name (CN).
    You can write the key and/or cert by specifying the key_out and/or cert_out parameters.
    If no arguments are supplied, the key and cert are kept in memory, the user will need to write them to a file.


    :param key_out: The path to write the private key to. If None, the private key will not be written to a file.
    :param cert_out: The path to write the certificate to. If None, the certificate will not be written to a file.
    :return: A tuple containing the private key and certificate data.
    """
    # Generate a new private key
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537, key_size=4096
    )

    # Create a certificate signing request (CSR)
    subject: x509.Name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "*.xlink.cn")]
    )
    csr: x509.CertificateSigningRequest = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    # Generate a self-signed certificate valid for 10 years
    issuer = subject
    cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )

    if any([key_out, cert_out]):
        cert_out = Path(cert_out)
        key_out = Path(key_out)
        chain_out = Path()

        if key_out is not None:
            # Write private key to file
            with key_out.open("wb") as key_file:
                key_file.write(
                    private_key.private_bytes(
                        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                    )
                )

        if cert_out is not None:
            # Write certificate to file
            with cert_out.open("wb") as cert_file:
                cert_file.write(cert.public_bytes(Encoding.PEM))
            chain_out = cert_out.parent / "server.pem"

        if key_out is not None and cert_out is not None:
            # Concatenate key.pem and cert.pem into server.pem
            with chain_out.open("wb") as server_pem:
                with key_out.open("rb") as key_pem:
                    server_pem.write(key_pem.read())
                with cert_out.open("rb") as cert_pem:
                    server_pem.write(cert_pem.read())

    return private_key, cert
