import datetime
import os
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Ruta a la base de datos
DB_PATH = "hospital.db"


# Usamos AES-GCM (AES en Galois/Counter Mode) para cifrar los datos.
# AES-GCM proporciona cifrado autenticado, lo que significa que los datos son cifrados y autenticados al mismo tiempo.

# Generar una clave de cifrado de 256 bits (32 bytes) para AES-GCM
def generar_clave():
    """
    Genera una clave segura para AES-GCM, utilizando una longitud de 256 bits (32 bytes).
    Esto asegura un nivel de cifrado adecuado para la protección de datos.
    """
    return os.urandom(32)  # Genera una clave aleatoria de 32 bytes


# Almacenar la clave maestra en la base de datos para recuperarla luego
def almacenar_clave(clave):
    """
    Guarda la clave maestra en una tabla en la base de datos.
    - Si la tabla no existe, la crea con los siguientes campos:
        - id: Identificador único de la clave maestra.
        - clave: Clave cifrada almacenada en formato BLOB (datos binarios).
    """
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clave_maestra (
            id INTEGER PRIMARY KEY,
            clave BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT OR REPLACE INTO clave_maestra (id, clave) VALUES (1, ?)", (clave,))
    conexion.commit()
    conexion.close()


# Recuperar la clave de la base de datos
def cargar_clave():
    """
    Recupera la clave maestra almacenada en la base de datos.
    - Si no se encuentra, lanza una excepción para notificar al usuario.
    """
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT clave FROM clave_maestra WHERE id = 1")
    row = cursor.fetchone()
    conexion.close()
    if row is None:
        raise ValueError("No se encontró una clave maestra.")
    return row[0]  # Devuelve la clave en formato binario (BLOB)


# mejora extra


def rotar_clave_si_necesario():
    ultima_rotacion = obtener_fecha_ultima_rotacion()
    hoy = datetime.date.today()
    if (hoy - ultima_rotacion).days > 90:
        nueva_clave = generar_clave()
        almacenar_clave(nueva_clave)
        actualizar_fecha_ultima_rotacion(hoy)


def obtener_fecha_ultima_rotacion():
    # Aquí leerías la última fecha de rotación almacenada en una tabla de metadatos
    pass


def actualizar_fecha_ultima_rotacion(fecha):
    # Aquí actualizarías la fecha de rotación en la base de datos
    pass


# Cifrar y autenticar datos utilizando AES-GCM
def cifrar_datos(datos, clave):
    """
    Cifra y autentica los datos usando AES-GCM.
    - datos (str): Datos en texto plano que se quieren cifrar.
    - clave (bytes): Clave utilizada para el cifrado.
    Retorna:
        - iv: Nonce de 12 bytes utilizado para este cifrado (único por mensaje).
        - texto_cifrado: Los datos cifrados.
        - tag: Etiqueta de autenticación para asegurar que los datos no fueron modificados.
    """
    iv = os.urandom(12)  # Nonce único para cada mensaje, necesario para AES-GCM
    cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    texto_cifrado = cifrador.update(datos.encode()) + cifrador.finalize()
    return iv, texto_cifrado, cifrador.tag


# Descifrar los datos recuperándolos de la base de datos
def descifrar_datos(mensaje_id):
    """
    Recupera y descifra un mensaje almacenado en la base de datos, asegurando su autenticidad.
    - mensaje_id (int): ID único del mensaje cifrado en la base de datos.
    Retorna el mensaje descifrado si la autenticación es exitosa.
    """
    clave = cargar_clave()  # Carga la clave maestra para descifrar los datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT iv, texto_cifrado, tag FROM datos_protegidos WHERE id = ?", (mensaje_id,))
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        raise ValueError("No se encontró el mensaje cifrado con el ID proporcionado.")

    iv, texto_cifrado, tag = row  # Recupera el nonce, los datos cifrados y la etiqueta de autenticación
    descifrador = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    datos_descifrados = descifrador.update(texto_cifrado) + descifrador.finalize()  # Si el tag no coincide, lanzará una excepción
    print("Datos descifrados exitosamente.")
    return datos_descifrados.decode()  # Devuelve el mensaje en texto plano


# Almacenar datos cifrados en la base de datos
def almacenar_datos_cifrados(mensaje):
    """
    Almacena los datos cifrados en la base de datos, junto con el nonce y la etiqueta de autenticación.
    - mensaje (str): Mensaje en texto plano que será cifrado.
    Almacena:
        - iv: Nonce único para este mensaje cifrado.
        - texto_cifrado: Los datos cifrados del mensaje.
        - tag: Etiqueta de autenticación generada por AES-GCM.
    """
    clave = cargar_clave()  # Carga la clave maestra para cifrar los datos
    iv, texto_cifrado, tag = cifrar_datos(mensaje, clave)

    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS datos_protegidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            iv BLOB NOT NULL,
            texto_cifrado BLOB NOT NULL,
            tag BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT INTO datos_protegidos (iv, texto_cifrado, tag) VALUES (?, ?, ?)", (iv, texto_cifrado, tag))
    conexion.commit()
    conexion.close()
    print("Mensaje cifrado y almacenado en la base de datos.")
