from hash import secure_hash

items = {
    "Word документ": "./documents/word.docx",
    "Файл з кодом": "./documents/source.py",
    "Зображення": "./documents/image.png"
}

bit_lengths = [2]

for name, item in items.items():
    print(f"\n=== {name} ===")
    for bits in bit_lengths:
        h = secure_hash(item, bit_length=bits)
        print(f"  {bits} біти => {h}")
