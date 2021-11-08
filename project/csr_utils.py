from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64

private_key = ec.generate_private_key(
    ec.SECP256R1()
)

with open("key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def get_csr(dns_names):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0]),
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(dns_name) for dns_name in dns_names
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA256())
    return base64url_enc(csr.public_bytes(serialization.Encoding.DER))


def base64url_enc(bytestring):
    return base64.urlsafe_b64encode(bytestring).rstrip(b'=')
