import logging
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# Hecho con https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def generar_claves(usuario_id):
    """Genera y guarda claves RSA para un usuario."""
    private_key = rsa.generate_private_key(  # Genera la clave privada
        public_exponent=65537,  # El exponente público de la nueva clave. Puede ser 65537 o 3, se debería usar 65537
        key_size=2048,  # se recomienda encarecidamente que sean de al menos 2048
    )

    # Serialización de las claves (private_key y public_key)
    # Si tienes una clave privada que has cargado se puede usar private_bytes() para serializar la clave.
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # Formato de serialización
        encryption_algorithm=serialization.BestAvailableEncryption(b"clave_secreta")  # Clave de encriptación
    )
    # Para claves públicas se puede usar public_bytes() para serializar la clave.
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,  # Formato de serialización
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Formato de serialización
    )

    # Crear directorio para el usuario
    user_dir = f"keys/{usuario_id}"  # Ruta de la carpeta del usuario
    os.makedirs(user_dir, exist_ok=True)  # Crea la carpeta si no existe

    # Guardar claves
    with open(f"{user_dir}/private_key.pem", "wb") as private_file:  # Guarda la clave privada
        private_file.write(private_pem)
    with open(f"{user_dir}/public_key.pem", "wb") as public_file:  # Guarda la clave publica
        public_file.write(public_pem)

    print(f"Claves generadas para el usuario: {usuario_id}")


# Key loading; Hecho con https://cryptography.io/en/latest/hazmat/primitives/asymmetric/
def generar_firma(usuario_id, archivo):
    """Genera una firma digital para un archivo usando la clave privada."""
    with open(f"keys/{usuario_id}/private_key.pem", "rb") as key_file:  # Carga la clave privada
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"clave_secreta"  # Clave de encriptación
        )
    # Signing (hecho con cryptography)
    with open(archivo, "rb") as file:  # Carga el archivo
        mensaje = file.read()

    firma = private_key.sign(  # Genera la firma
        mensaje,  # Mensaje a firmar
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # MGF (Mask Generation Function)
            salt_length=padding.PSS.MAX_LENGTH  # Longitud del salto
        ),
        hashes.SHA256()  # Algoritmo de hash
    )

    with open(f"{archivo}.sig", "wb") as sig_file:  # Guarda la firma
        sig_file.write(firma)

    print(f"Firma generada para el archivo: {archivo}")


# Verification; Hecho con https://cryptography.io/en/latest/hazmat/primitives/asymmetric/
def verificar_firma(usuario_id, archivo):
    """Verifica la firma de un archivo con la clave pública del usuario"""
    with open(f"keys/{usuario_id}/public_key.pem", "rb") as key_file:  # Carga la clave publica
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(archivo, "rb") as file:  # Carga el archivo
        data = file.read()

    with open(f"{archivo}.sig", "rb") as sig_file:  # Carga la firma
        firma = sig_file.read()

    try:  # Verifica la firma
        public_key.verify(
            firma,  # Firma
            data,  # Mensaje
            padding.PSS(  # Padding
                mgf=padding.MGF1(hashes.SHA256()),  # MGF
                salt_length=padding.PSS.MAX_LENGTH  # Longitud del salto
            ),
            hashes.SHA256()  # Algoritmo de hash
        )
        print(f"La firma es válida para el archivo: {archivo}")
        return True  # Retorna True si la firma es válida

    except Exception as e:  # Si la firma es inválida
        print(f"Firma inválida: {e}")  # Imprime el error
        return False


# Configuración del log, con libreria logging
# Hecho con https://docs.python.org/3/howto/logging.html
logging.basicConfig(filename="firma_digital.log",  # Ruta del archivo de log
                    level=logging.INFO,  # Nivel de log
                    format="%(asctime)s - %(message)s"  # Formato del log (fecha y mensaje)
                    # asctime es la fecha y hora del log en formato RFC 2822
                    # message es el mensaje del log
                    )


# Función para registrar un mensaje en el log
def registrar_log(mensaje):
    logging.info(mensaje)


if __name__ == '__main__':
    generar_claves("usuario123")  # Genera las claves
    generar_firma("usuario123", "documento.txt")  # Genera la firma
    resultado = verificar_firma("usuario123", "documento.txt")  # Verifica la firma
    registrar_log(f"Verificación de firma para documento.txt: {'Válida' if resultado else 'Inválida'}")  # Registra el resultado
