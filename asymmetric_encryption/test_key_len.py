from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import random
import string

letters = string.ascii_lowercase


my_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048 * 4,
    backend=default_backend()
)

my_public_key = my_private_key.public_key()

for length in range(1, 1000, 100):
    encrypted = my_public_key.encrypt(
        ''.join(random.choice(letters) for i in range(length)).encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'{length} encrypted')
