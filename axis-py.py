import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

private_key_pem = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/8Vjz1glMyPv0
... (your private key here) ...
-----END PRIVATE KEY-----
"""

data_to_encode = {
    "Data": {
        "userName": "alwebuser",
        "password": "acid_qa",
    },
    "Risks": {},
}


def load_private_key(pem_key):
    return serialization.load_pem_private_key(
        pem_key.encode(),
        password=None,
        backend=default_backend(),
    )


def run():
    try:
        # Load private key
        private_key = load_private_key(private_key_pem)

        # Create JWS
        encoded_token = jwt.encode(data_to_encode, private_key, algorithm='RS256')

        # Make HTTP request
        url = 'https://sakshamuat.axisbank.co.in/gateway/api/v2/CRMNext/login'
        headers = {
            'Content-Type': 'application/jose+json',
        }

        response = requests.post(url, data=encoded_token, headers=headers)

        print('API Response:', response.text)
    except Exception as e:
        print('Error:', str(e))

run()
