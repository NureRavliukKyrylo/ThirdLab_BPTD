from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pad(data, block_size):
    # Доповнення повідомлення нульовими байтами до кратності розміру блоку
    padding_len = (block_size - len(data) % block_size) % block_size
    return data + b'\x00' * padding_len

def xor_bytes(a, b):
    # Побітова операція XOR для двох байтових послідовностей
    return bytes(x ^ y for x, y in zip(a, b))

def secure_hash(data, bit_length=8, block_size=16):
    # Перевірка допустимої довжини результату хешу
    if bit_length not in [2, 4, 8]:
        raise ValueError("bit_length має бути 2, 4 або 8")

    # Перетворення вхідних даних у байтовий формат
    # Підтримується текст, байти або шлях до файлу
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

    # Вирівнювання довжини повідомлення під розмір блоку AES
    data_bytes = pad(data_bytes, block_size)
    num_blocks = len(data_bytes) // block_size

    # Початкове значення хешу (H₀)
    H = b'\x00' * block_size

    backend = default_backend()

    # Поблочна ітеративна обробка повідомлення
    for i in range(num_blocks):
        block = data_bytes[i * block_size:(i+1) * block_size]

        # Поточний блок використовується як ключ AES
        cipher = Cipher(algorithms.AES(block), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()

        # Реалізація формули Hᵢ = Eₐ(B) ⊕ C
        # Eₐ(B) — AES-шифрування попереднього хешу
        # C — XOR комбінація поточного блоку та попереднього хешу
        H = xor_bytes(encryptor.update(H), xor_bytes(block, H))

    # Усічення результату до 2, 4 або 8 біт
    last_byte = H[-1]
    truncated = last_byte & ((1 << bit_length) - 1)

    # Повернення хешу у вигляді бітового рядка
    return format(truncated, f'0{bit_length}b')

def bit_difference(h1, h2):
    return sum(b1 != b2 for b1, b2 in zip(h1, h2))

if __name__ == "__main__":
    original_text = "Cryptographic hash function"
    modified_text = "cryptographic hash function" 

    print("Оригінальний текст: ", original_text)
    print("Змінений текст:     ", modified_text)
    print()

    for bits in [2, 4, 8]:
        h1 = secure_hash(original_text, bit_length=bits)
        h2 = secure_hash(modified_text, bit_length=bits)

        diff = bit_difference(h1, h2)
        percentage = (diff / bits) * 100

        print(f"Хеш ({bits} біт):")
        print(f"  H(оригінал) = {h1}")
        print(f"  H(зміна)    = {h2}")
        print(f"  Змінено бітів: {diff} з {bits} ({percentage:.1f}%)")

        if percentage >= 30:
            print(" Виконується вимога ≥ 30% лавинного ефекту")
        else:
            print(" Лавинний ефект недостатній")

        print()