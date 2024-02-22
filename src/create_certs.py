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
    write_to_file: bool = False,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed certificate and private key using *.xlink.cn for Common Name (CN).


    :param key_out: The path to write the private key to. If None, the private key will not be written to a file.
    :param cert_out: The path to write the certificate to. If None, the certificate will not be written to a file.
    :param write_to_file: If True, the private key and certificate will be written to the paths specified by
    key_out and cert_out.
    :return: A tuple containing the private key and certificate.
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

    if write_to_file:
        cert_out = Path(cert_out)
        key_out = Path(key_out)
        chain_out = cert_out.parent / "server.pem"

        # Write private key to file
        with open(key_out, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                )
            )

        # Write certificate to file
        with open(cert_out, "wb") as cert_file:
            cert_file.write(cert.public_bytes(Encoding.PEM))

        # Concatenate key.pem and cert.pem into server.pem
        with open(chain_out, "wb") as server_pem:
            with open(key_out, "rb") as key_pem:
                server_pem.write(key_pem.read())
            with open(cert_out, "rb") as cert_pem:
                server_pem.write(cert_pem.read())

    return private_key, cert
