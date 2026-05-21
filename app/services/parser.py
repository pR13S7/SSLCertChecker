from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from datetime import datetime, timezone


def parse_certificate(pem_text: str) -> dict:
    pem_bytes = pem_text.strip().encode("utf-8")
    cert = x509.load_pem_x509_certificate(pem_bytes)

    return {
        "subject": _name_to_dict(cert.subject),
        "issuer": _name_to_dict(cert.issuer),
        "serial_number": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "is_expired": datetime.now(timezone.utc) > cert.not_valid_after_utc,
        "days_remaining": (cert.not_valid_after_utc - datetime.now(timezone.utc)).days,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key": _public_key_info(cert.public_key()),
        "extensions": _parse_extensions(cert),
        "fingerprints": {
            "sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
            "sha1": cert.fingerprint(hashes.SHA1()).hex(":"),
        },
        "version": cert.version.name,
        "is_self_signed": cert.issuer == cert.subject,
    }


def _name_to_dict(name: x509.Name) -> dict:
    result = {}
    for attr in name:
        key = attr.oid._name
        result[key] = attr.value
    return result


def _public_key_info(key) -> dict:
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": key.key_size}
    elif isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "curve": key.curve.name, "bits": key.key_size}
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return {"type": type(key).__name__.replace("PublicKey", "")}
    return {"type": "Unknown"}


def _parse_extensions(cert: x509.Certificate) -> list:
    extensions = []
    for ext in cert.extensions:
        entry = {"name": ext.oid._name, "critical": ext.critical}
        try:
            if isinstance(ext.value, x509.SubjectAlternativeName):
                entry["san"] = ext.value.get_values_for_type(x509.DNSName)
            elif isinstance(ext.value, x509.BasicConstraints):
                entry["ca"] = ext.value.ca
            elif isinstance(ext.value, x509.KeyUsage):
                entry["usages"] = [
                    u for u in [
                        "digital_signature", "key_encipherment",
                        "content_commitment", "data_encipherment",
                        "key_agreement", "key_cert_sign", "crl_sign",
                    ] if getattr(ext.value, u, False)
                ]
        except Exception:
            pass
        extensions.append(entry)
    return extensions
