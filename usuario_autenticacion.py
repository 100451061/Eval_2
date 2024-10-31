import os
import re
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Ruta a la base de datos
DB_PATH = "hospital.db"


# Inicializa la base de datos para almacenar usuarios
# Utiliza SQLite para crear una tabla en la base de datos si aún no existe.
# La tabla 'usuarios' almacena:
# - usuario: Nombre de usuario, que actúa como clave primaria para evitar duplicados.
# - salt: Salt aleatorio que se usará en la función Scrypt para la derivación de la contraseña.
# - pwd_hash: Hash derivado de la contraseña usando Scrypt, almacenado como BLOB (Binary Large Object).
def inicializar_bd():
    """
    Inicializa la base de datos y crea la tabla 'usuarios' si no existe.
    Esta tabla almacena:
    - usuario: Nombre de usuario como clave primaria.
    - salt: Salt (valor único y aleatorio) en formato BLOB (dato binario), que asegura la
            unicidad del hash incluso si se usa la misma contraseña.
    - pwd_hash: Hash de la contraseña, también en formato BLOB, para asegurar la confidencialidad
                de la contraseña en la base de datos.
    """
    conexion = sqlite3.connect(DB_PATH)  # Conecta a la base de datos SQLite especificada en DB_PATH
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            usuario TEXT PRIMARY KEY,
            salt BLOB NOT NULL,  
            pwd_hash BLOB NOT NULL  
        )
    ''')
    conexion.commit()  # Confirma los cambios en la base de datos
    conexion.close()  # Cierra la conexión a la base de datos


# Función para generar el hash de la contraseña usando Scrypt
# Utiliza Scrypt, un algoritmo que ayuda a derivar claves de forma segura, haciéndolo más resistente a ataques de fuerza bruta.
# Se usa un salt único y un factor de dificultad (n, r, p) que hace que el hash sea costoso de calcular, aumentando la seguridad.
def generar_pwd_hash(contrasena, salt):
    """
    Genera un hash seguro de la contraseña usando Scrypt.
    - contrasena (str): La contraseña en texto plano que el usuario quiere proteger.
    - salt (bytes): Valor aleatorio único que garantiza un hash único incluso si dos usuarios tienen la misma contraseña.
    Retorna el hash resultante en bytes.
    """
    kdf = Scrypt(
        salt=salt,  # Salt único y aleatorio para asegurar que el mismo texto de contraseña produzca diferentes hashes.
        length=32,  # La longitud del hash generado en bytes, aquí 32 bytes (256 bits) para asegurar un nivel de seguridad adecuado.
        n=2 ** 14,  # Factor de costo de CPU. Un valor más alto hace que el cálculo sea más lento, aumentando la resistencia a ataques.
        r=8,  # Factor de costo de memoria, haciendo que se necesite más memoria para calcular el hash.
        p=1,  # Factor de paralelización, controlando el número de operaciones simultáneas en el cálculo.
        backend=default_backend()
    )
    return kdf.derive(contrasena.encode())  # Convierte la contraseña en una clave derivada en bytes usando Scrypt.


# mejora extra :) nos aseguramos de tener al menos 8 caracteres y contener letras y números
def validar_datos_usuario(usuario, contrasena):
    if not re.match("^[A-Za-z0-9]+$", usuario):
        raise ValueError("El nombre de usuario debe contener solo letras y números.")
    if len(contrasena) < 8 or not re.search("[A-Za-z]", contrasena) or not re.search("[0-9]", contrasena):
        raise ValueError("La contraseña debe tener al menos 8 caracteres y contener letras y números.")


# Registra un nuevo usuario en la base de datos
# Esta función toma el nombre de usuario y la contraseña, y luego deriva un hash seguro de la contraseña.
# Almacena el nombre de usuario, el salt, y el hash en la tabla 'usuarios'.
def registrar_usuario(usuario, contrasena):
    """
    Registra un nuevo usuario en la base de datos con un hash de contraseña seguro.
    - usuario (str): Nombre del usuario que se quiere registrar.
    - contrasena (str): Contraseña en texto plano.
    """
    salt = os.urandom(16)  # Genera un salt aleatorio de 16 bytes para usar en el hashing de la contraseña.
    pwd_hash = generar_pwd_hash(contrasena, salt)  # Genera el hash de la contraseña usando el salt generado.

    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("INSERT INTO usuarios (usuario, salt, pwd_hash) VALUES (?, ?, ?)", (usuario, salt, pwd_hash))
    conexion.commit()
    conexion.close()
    print(f"Usuario '{usuario}' registrado exitosamente.")  # Mensaje informativo sobre el registro exitoso del usuario.


# Autenticación de un usuario
# Esta función verifica la contraseña ingresada con la almacenada en la base de datos.
# Intenta generar el mismo hash y lo compara para determinar si la contraseña ingresada es correcta.
def autenticar_usuario(usuario, contrasena):
    """
    Verifica si la contraseña ingresada coincide con el hash almacenado para un usuario.
    - usuario (str): Nombre de usuario.
    - contrasena (str): Contraseña en texto claro que se va a verificar.
    Retorna un mensaje que indica si la autenticación fue exitosa o fallida.
    """
    # Recuperar el salt y el hash de la base de datos para el usuario dado
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT salt, pwd_hash FROM usuarios WHERE usuario = ?", (usuario,))
    row = cursor.fetchone()
    conexion.close()

    if not row:
        return "Usuario no encontrado"  # Mensaje de error si el usuario no existe en la base de datos.

    salt, stored_pwd_hash = row  # Desempaqueta el salt y el hash almacenado en la base de datos.

    # Intentar verificar el hash usando la contraseña ingresada
    try:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=default_backend()
        )
        kdf.verify(contrasena.encode(), stored_pwd_hash)  # Verifica si el hash coincide con la contraseña.
        return "Autenticación exitosa"
    except Exception:
        return "Contraseña incorrecta"  # Mensaje de error si la contraseña ingresada es incorrecta.


# Genera un HMAC (Hash-based Message Authentication Code)
# Usado para asegurar la integridad de un mensaje y verificar que no haya sido alterado.
# Un HMAC toma el mensaje y una clave secreta, y genera un código que sólo es posible verificar con la misma clave.
def generar_hmac(mensaje, clave):
    """
    Genera un código HMAC para verificar la integridad de un mensaje.
    - mensaje (bytes): Mensaje que se quiere proteger.
    - clave (bytes): Clave secreta utilizada para generar el HMAC.
    Retorna el HMAC del mensaje.
    """
    h = hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h.update(mensaje)  # Agrega el mensaje al objeto HMAC
    return h.finalize()  # Devuelve el HMAC calculado.


# Inicialización de la base de datos para asegurar que la tabla exista antes de comenzar
inicializar_bd()
