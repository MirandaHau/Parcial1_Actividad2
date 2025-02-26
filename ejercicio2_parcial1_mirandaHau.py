from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, create_string_object
import os

# Paso 1: Generar claves RSA para Alice y la AC con e = 65537 (4to número de Fermat)
def generate_keys():
    key = RSA.generate(1024, e=65537)  # 1024 bits y e=65537
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

alice_private, alice_public = generate_keys()
ac_private, ac_public = generate_keys()

# Guardar claves en archivos
keys = {"alice_private.pem": alice_private, "alice_public.pem": alice_public,
        "ac_private.pem": ac_private, "ac_public.pem": ac_public}
for filename, key in keys.items():
    with open(filename, "wb") as f:
        f.write(key)

# Paso 2: Calcular hash del PDF en bloques
def hash_document(filename):
    try:
        hash_obj = SHA256.new()
        with open(filename, "rb") as f:
            while chunk := f.read(4096):  # Leer en bloques de 4 KB
                hash_obj.update(chunk)
        return hash_obj
    except FileNotFoundError:
        print("Error: No se encontró el archivo PDF.")
        exit(1)

hash_obj = hash_document("NDA.pdf")

# Paso 3: Alice firma el hash con su clave privada
def sign_hash(hash_obj, private_key):
    key = RSA.import_key(private_key)
    signature = pkcs1_15.new(key).sign(hash_obj)
    return signature

alice_signature = sign_hash(hash_obj, alice_private)

# Paso 4: Agregar la firma de Alice al PDF en los metadatos
reader = PdfReader("NDA.pdf")
writer = PdfWriter()
for page in reader.pages:
    writer.add_page(page)

metadata = reader.metadata
metadata[NameObject("/AliceSignature")] = create_string_object(alice_signature.hex())  # Usamos NameObject para las claves y create_string_object para los valores
writer.add_metadata(metadata)
with open("NDA_signed_by_Alice.pdf", "wb") as f:
    writer.write(f)

# Paso 5: AC verifica la firma de Alice
def verify_signature(hash_obj, signature, public_key):
    key = RSA.import_key(public_key)
    try:
        pkcs1_15.new(key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

alice_signature_valid = verify_signature(hash_obj, alice_signature, alice_public)
print("Firma de Alice válida:", alice_signature_valid)

# Paso 6: La AC firma el documento con su clave privada
ac_signature = sign_hash(hash_obj, ac_private)

# Paso 7: Agregar la firma de la AC al PDF en los metadatos
metadata[NameObject("/ACSignature")] = create_string_object(ac_signature.hex())  # Usamos NameObject para las claves y create_string_object para los valores
writer.add_metadata(metadata)
with open("NDA_signed_by_AC.pdf", "wb") as f:
    writer.write(f)

# Simulando la verificación de Bob de la firma de la AC
ac_signature_valid_bob = verify_signature(hash_obj, ac_signature, ac_public)
print("Firma de la AC válida para Bob:", ac_signature_valid_bob)

# Paso 8: Bob verifica la firma de la AC
ac_signature_valid = verify_signature(hash_obj, ac_signature, ac_public)
print("Firma de la AC válida:", ac_signature_valid)