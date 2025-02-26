import Crypto.Random
import Crypto.Util.number
import hashlib

# Para e vamos a usar el número 4 de Fermat
e = 65537

# Paso 1: Generación manual de las claves RSA de Alice y la AC
def generate_keypair():
    p = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = Crypto.Util.number.inverse(e, phi)
    return n, d

# Claves de Alice
nA, dA = generate_keypair()
print("\nRSA de Alice: n =", nA)
print("Clave privada de Alice: d =", dA)

# Claves de la AC
nAc, dAc = generate_keypair()
print("\nRSA de la AC: n =", nAc)
print("Clave privada de la AC: d =", dAc)

# Paso 2: Leer el archivo NDA.pdf y calcular el hash
nda = 'NDA.pdf'

try:
    with open(nda, 'rb') as file:
        file_content = file.read()

    print(f'\nMensaje: {nda}')
except FileNotFoundError:
    print(f'\nError: No se encontró el archivo {nda}')
    exit(1)

# Calcular el hash del documento
hM = int.from_bytes(hashlib.sha256(file_content).digest(), byteorder='big')
print('\nMensaje hasheado:', hex(hM))

# Paso 3: Alice firma el hash con su clave privada
sA = pow(hM, dA, nA)  # Firma el hash de manera manual usando RSA
print('\nFirma de Alice:', sA)

# Paso 4: La AC verifica la firma de Alice usando la clave pública de Alice
hM1 = pow(sA, e, nA)  # Verificación usando la fórmula pública
print('\nLa AC verifica el hash:', hex(hM1))

if hM == hM1:
    print("\nFirma de Alice validada. Mandando a la AC...")
else:
    print("Error: Los hashes no coinciden.")
    exit(1)

# Paso 5: La AC firma el hash con su clave privada
sAc = pow(hM, dAc, nAc)  # Firma el hash de manera manual usando la clave privada de la AC
print('\nFirma de la AC:', sAc)

# Paso 6: Bob verifica la firma de la AC usando la clave pública de la AC
hM2 = pow(sAc, e, nAc)  # Verificación usando la fórmula pública de la AC
print('\nBob verifica la firma de la AC:', hex(hM2))

# Verificar que Bob ha recibido correctamente el mensaje firmado por la AC
print("\nBob recibió correctamente el mensaje firmado por la AC:", (hM1 == hM2))