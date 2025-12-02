from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pad(data, block_size):
    padding_len = (block_size - len(data) % block_size) % block_size
    return data + b'\x00' * padding_len

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def secure_hash(data, bit_length=8, block_size=16):
    if bit_length not in [2, 4, 8]:
        raise ValueError("bit_length має бути 2, 4 або 8")

    if isinstance(data, str):
        try:
            with open(data, "rb") as f:
                data_bytes = f.read()
        except FileNotFoundError:
            data_bytes = data.encode('utf-8')
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError("data має бути str або bytes")

    data_bytes = pad(data_bytes, block_size)
    num_blocks = len(data_bytes) // block_size

    H = b'\x00' * block_size

    backend = default_backend()

    for i in range(num_blocks):
        block = data_bytes[i * block_size:(i+1) * block_size]
        cipher = Cipher(algorithms.AES(block), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()

        H = xor_bytes(encryptor.update(H), xor_bytes(block, H))

    last_byte = H[-1]
    truncated = last_byte & ((1 << bit_length) - 1)

    return format(truncated, f'0{bit_length}b')