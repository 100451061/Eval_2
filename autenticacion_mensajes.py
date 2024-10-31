import os
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# Ruta de la base de datos
DB_PATH = "hospital.db"


# Generar clave secreta para HMAC
def generar_clave_hmac():
    """
    Genera una clave secreta aleatoria de 256 bits para HMAC.
    Esta clave se utilizará para asegurar la autenticidad de los mensajes.
    """
    return os.urandom(32)  # Clave de 256 bits para HMAC


# Almacenar la clave HMAC en la base de datos
def almacenar_clave_hmac():
    """
    Almacena la clave HMAC en la base de datos.
    - Crea la tabla 'clave_hmac' si no existe, con los campos:
        - id: Identificador de la clave (único)
        - clave: La clave HMAC en formato binario (BLOB)
    - Inserta o reemplaza la clave en el registro con id=1.
    """
    clave_hmac = generar_clave_hmac()
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clave_hmac (
            id INTEGER PRIMARY KEY,
            clave BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT OR REPLACE INTO clave_hmac (id, clave) VALUES (1, ?)", (clave_hmac,))
    conexion.commit()
    conexion.close()


# Cargar la clave HMAC desde la base de datos
def cargar_clave_hmac():
    """
    Recupera la clave HMAC de la base de datos.
    - Busca la clave en la tabla 'clave_hmac' con id=1.
    - Si no se encuentra la clave, lanza un error de valor.
    """
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT clave FROM clave_hmac WHERE id = 1")
    row = cursor.fetchone()
    conexion.close()
    if row is None:
        raise ValueError("No se encontró una clave HMAC.")
    return row[0]


# Generar HMAC para un mensaje
def generar_hmac(mensaje):
    """
    Genera un código HMAC para el mensaje proporcionado.
    - mensaje (str): Texto que queremos autenticar.
    - Retorna el HMAC generado en formato binario.
    """
    clave_hmac = cargar_clave_hmac()
    h = hmac.HMAC(clave_hmac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje.encode())  # Actualiza el HMAC con el mensaje en bytes
    return h.finalize()  # Finaliza y devuelve el HMAC


# Almacenar mensaje y su HMAC en la base de datos
def almacenar_mensaje(mensaje):
    """
    Almacena un mensaje y su HMAC en la base de datos para futuras verificaciones.
    - Crea la tabla 'mensajes_autenticados' si no existe, con los campos:
        - id: Identificador único del mensaje.
        - mensaje: El texto del mensaje.
        - hmac: El código HMAC asociado al mensaje.
    - Inserta el mensaje y su HMAC en la tabla.
    """
    hmac_code = generar_hmac(mensaje)
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mensajes_autenticados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mensaje TEXT NOT NULL,
            hmac BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT INTO mensajes_autenticados (mensaje, hmac) VALUES (?, ?)", (mensaje, hmac_code))
    conexion.commit()
    conexion.close()
    print("Mensaje autenticado y almacenado en la base de datos.")


# Verificar la autenticidad de un mensaje
def verificar_mensaje(mensaje_id, mensaje):
    """
    Verifica la autenticidad de un mensaje usando su ID y HMAC almacenado.
    - mensaje_id (int): ID del mensaje en la base de datos.
    - mensaje (str): Texto del mensaje para verificar.
    - Retorna True si el HMAC coincide; False si no coincide o si el mensaje no es auténtico.
    """
    clave_hmac = cargar_clave_hmac()
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT hmac FROM mensajes_autenticados WHERE id = ?", (mensaje_id,))
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        raise ValueError("No se encontró el mensaje en la base de datos.")

    hmac_almacenado = row[0]  # Obtiene el HMAC almacenado para el mensaje

    # Verificar el HMAC
    h = hmac.HMAC(clave_hmac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje.encode())  # Recalcula el HMAC del mensaje proporcionado
    try:
        h.verify(hmac_almacenado)  # Compara el HMAC recalculado con el almacenado
        print("El mensaje es auténtico.")
        return True
    except Exception:
        print("El mensaje no es auténtico.")
        return False
