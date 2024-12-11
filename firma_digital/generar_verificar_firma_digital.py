import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


def generar_claves(usuario_id):
    """Genera y guarda claves RSA para un usuario."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Longitud segura recomendada
    )

    # Serialización de las claves
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"clave_secreta")
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Crear directorio para el usuario
    user_dir = f"keys/{usuario_id}"
    os.makedirs(user_dir, exist_ok=True)

    # Guardar claves
    with open(f"{user_dir}/private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
    with open(f"{user_dir}/public_key.pem", "wb") as public_file:
        public_file.write(public_pem)

    print(f"Claves generadas para el usuario: {usuario_id}")


def generar_firma(usuario_id, archivo):
    """Genera una firma digital para un archivo usando la clave privada."""
    with open(f"keys/{usuario_id}/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"clave_secreta"
        )

    with open(archivo, "rb") as file:
        data = file.read()

    firma = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(f"{archivo}.sig", "wb") as sig_file:
        sig_file.write(firma)

    print(f"Firma generada para el archivo: {archivo}")


def verificar_firma(usuario_id, archivo):
    """Verifica la firma de un archivo con la clave pública del usuario."""
    with open(f"keys/{usuario_id}/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(archivo, "rb") as file:
        data = file.read()

    with open(f"{archivo}.sig", "rb") as sig_file:
        firma = sig_file.read()

    try:
        public_key.verify(
            firma,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"La firma es válida para el archivo: {archivo}")
        return True
    except Exception as e:
        print(f"Firma inválida: {e}")
        return False


# Configuración del log
logging.basicConfig(filename="firma_digital.log", level=logging.INFO, format="%(asctime)s - %(message)s")


def registrar_log(mensaje):
    """Registra un mensaje en el log."""
    logging.info(mensaje)


if __name__ == '__main__':
    generar_claves("usuario123")
    generar_firma("usuario123", "documento.txt")
    resultado = verificar_firma("usuario123", "documento.txt")
    registrar_log(f"Verificación de firma para documento.txt: {'Válida' if resultado else 'Inválida'}")
