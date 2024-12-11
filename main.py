import logging  # esta libreria es para el log
import re  # esta libreria es para la validacion de usuario y contraseña
import sqlite3  # esta libreria es para la base de datos
import tkinter as tk  # esta libreria es para la interfaz gráfica
from tkinter import messagebox, Toplevel  # messagebox es para mostrar mensajes, Toplevel es para crear ventanas secundarias

from autenticacion_mensajes import almacenar_mensaje, verificar_mensaje
from cifrado_simetrico import almacenar_datos_cifrados, descifrar_datos
from firma_digital.generar_verificar_firma_digital import generar_claves, generar_firma, verificar_firma  # (Eval 2)
from usuario_autenticacion import registrar_usuario, autenticar_usuario

# Configuración de logging para el log
logging.basicConfig(filename="cryptography.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")  # asctime es la fecha y hora del log en formato RFC 2822


# Validación de usuario y contraseña
def validar_datos_usuario(usuario, contrasena):  # esta funcion es para validar el usuario y la contrasena

    # este if es para que el usuario solo contenga letras y numeros
    if not re.match("^[A-Za-z0-9]+$", usuario):
        raise ValueError("El nombre de usuario debe contener solo letras y números.")

    # esta validacion es para que la contrasena tenga al menos 8 caracteres y contener letras y numeros
    if len(contrasena) < 8 or not re.search("[A-Za-z]", contrasena) or not re.search("[0-9]", contrasena):
        raise ValueError("La contraseña debe tener al menos 8 caracteres y contener letras y números.")


# Ruta de la base de datos
DB_PATH = "hospital.db"  # esta es la ruta de la base de datos

# Configuración de la ventana principal de la aplicación
root = tk.Tk()
root.title("Sistema de Seguridad del Hospital - Inicio de Sesión")
root.geometry("400x400")  # esta es la dimension de la ventana
root.configure(bg="grey")  # esta es la color de fondo, el color es gris

# Variables para almacenar entradas de usuario
usuario_var = tk.StringVar()  # esta es la variable para el usuario
contrasena_var = tk.StringVar()  # esta es la variable para la contraseña
mensaje_var = tk.StringVar()  # esta es la variable para el mensaje
mensaje_id_var = tk.StringVar()  # esta es la variable para el id del mensaje

# Título principal de la interfaz gráfica
# root es la ventana principal, text es el texto, font es la fuente, bg es el color de fondo, fg es el color del texto
# pack es para colocar el widget en la ventana
# pady es el espacio vertical entre el texto y los widgets de la ventana
tk.Label(root, text="Hospital Gregorio Marañón \n Sec Hosp", font=("Arial", 16, "bold"), bg="grey", fg="#333").pack(pady=(10, 20))


# Función para registrar usuarios
def registrar():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    try:
        validar_datos_usuario(usuario, contrasena)
        registrar_usuario(usuario, contrasena)
        messagebox.showinfo("Registro", f"Usuario '{usuario}' registrado exitosamente.")
        logging.info(f"Usuario '{usuario}' registrado exitosamente.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        logging.error(f"Error al registrar usuario '{usuario}': {e}")


# Función para autenticar usuarios
def autenticar():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    resultado = autenticar_usuario(usuario, contrasena)
    if resultado == "Autenticación exitosa":
        messagebox.showinfo("Autenticación", resultado)
        abrir_ventana_mensajes()
        logging.info(f"Usuario '{usuario}' autenticado exitosamente.")
    else:
        messagebox.showwarning("Autenticación", resultado)
        logging.warning(f"Intento de autenticación fallido para el usuario '{usuario}'.")


# Función para borrar un usuario de la base de datos
def borrar_usuario():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    resultado = autenticar_usuario(usuario, contrasena)
    if resultado == "Autenticación exitosa":
        try:
            conexion = sqlite3.connect(DB_PATH)
            cursor = conexion.cursor()
            cursor.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario,))
            conexion.commit()
            conexion.close()
            messagebox.showinfo("Borrar Usuario", f"Usuario '{usuario}' ha sido eliminado.")
            logging.info(f"Usuario '{usuario}' ha sido eliminado de la base de datos.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            logging.error(f"Error al borrar usuario '{usuario}': {e}")
    else:
        messagebox.showwarning("Autenticación Fallida", "Usuario o contraseña incorrectos.")
        logging.warning(f"Intento fallido de eliminación de usuario '{usuario}' por autenticación fallida.")


# Función para abrir la ventana de gestión de mensajes y firmas
def abrir_ventana_mensajes():
    ventana_mensajes = Toplevel(root)  # Toplevel es para crear una ventana secundaria
    ventana_mensajes.title("Sistema de Seguridad del Hospital")  # esto es el titulo de la ventana
    ventana_mensajes.geometry("400x600")  # esta es la dimension de la ventana
    ventana_mensajes.configure(bg="grey")  # esta es el color de fondo gris

    campos = [
        ("Usuario", usuario_var),
        ("Mensaje o Archivo", mensaje_var)
    ]

    for texto, variable in campos:
        tk.Label(ventana_mensajes, text=texto, bg="grey", font=("Arial", 12)).pack(pady=5)
        tk.Entry(ventana_mensajes, textvariable=variable, width=40).pack(pady=5)

    botones = [
        ("Cifrar Mensaje", cifrar_mensaje),
        ("Descifrar Mensaje", descifrar_mensaje),
        ("Autenticar Mensaje", autenticar_mensaje),
        ("Verificar Autenticidad", verificar_autenticidad),
        ("Generar Claves", generar_claves_gui),
        ("Firmar Archivo", firmar_archivo_gui),
        ("Verificar Firma", verificar_firma_gui),
        ("Salir", ventana_mensajes.destroy, "yellow", "black")
    ]

    for texto, comando, *color in botones:
        bg = color[0] if color else "#007bff"
        fg = color[1] if len(color) > 1 else "white"
        tk.Button(ventana_mensajes, text=texto, command=comando, bg=bg, fg=fg, width=20).pack(pady=5)


# Funciones auxiliares para cifrado y firmas
def cifrar_mensaje():
    try:
        almacenar_datos_cifrados(mensaje_var.get())
        messagebox.showinfo("Cifrado", "Mensaje cifrado y almacenado correctamente.")
    except Exception as e:
        mostrar_error("Error al cifrar mensaje", e)


def descifrar_mensaje():
    try:
        mensaje = descifrar_datos(int(mensaje_id_var.get()))
        messagebox.showinfo("Descifrado", f"Mensaje descifrado: {mensaje}")
    except Exception as e:
        mostrar_error("Error al descifrar mensaje", e)


def autenticar_mensaje():
    try:
        almacenar_mensaje(mensaje_var.get())
        messagebox.showinfo("Autenticación", "Mensaje autenticado correctamente.")
    except Exception as e:
        mostrar_error("Error al autenticar mensaje", e)


def verificar_autenticidad():
    try:
        if verificar_mensaje(int(mensaje_id_var.get()), mensaje_var.get()):
            messagebox.showinfo("Verificación", "El mensaje es aut\u00e9ntico.")
        else:
            messagebox.showwarning("Verificación", "El mensaje no es aut\u00e9ntico.")
    except Exception as e:
        mostrar_error("Error al verificar autenticidad", e)


# Funciones para limpiar tablas específicas en la base de datos
def limpiar_usuarios():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM usuarios")
    conexion.commit()
    conexion.close()
    messagebox.showinfo("Limpiar Usuarios", "Todos los usuarios han sido eliminados.")
    logging.info("Todos los usuarios han sido eliminados de la base de datos.")


def limpiar_mensajes_cifrados():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM datos_protegidos")
    conexion.commit()
    conexion.close()
    messagebox.showinfo("Limpiar Mensajes Cifrados", "Todos los mensajes cifrados han sido eliminados.")
    logging.info("Todos los mensajes cifrados han sido eliminados de la base de datos.")


def limpiar_mensajes_autenticados():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM mensajes_autenticados")
    conexion.commit()
    conexion.close()
    messagebox.showinfo("Limpiar Mensajes Autenticados", "Todos los mensajes autenticados han sido eliminados.")
    logging.info("Todos los mensajes autenticados han sido eliminados de la base de datos.")


def generar_claves_gui():  # (Eval 2)
    try:
        generar_claves(usuario_var.get())  # Genera las claves en la carpeta del usuario correspondiente
        messagebox.showinfo("Claves", "Claves generadas correctamente.")
    except Exception as e:  # Si ocurre un error al generar las claves se imprime un mensaje de error
        mostrar_error("Error al generar claves", e)


def firmar_archivo_gui():  # (Eval 2)
    try:
        generar_firma(usuario_var.get(), mensaje_var.get())  # Genera la firma del archivo en la carpeta del usuario correspondiente
        messagebox.showinfo("Firma", "Archivo firmado correctamente.")
    except Exception as e:  # Si ocurre un error al firmar el archivo se imprime un mensaje de error
        mostrar_error("Error al firmar archivo", e)


def verificar_firma_gui():  # (Eval 2)
    try:
        if verificar_firma(usuario_var.get(), mensaje_var.get()):  # Verifica la firma del archivo en la carpeta del usuario correspondiente
            messagebox.showinfo("Verificación", "Firma válida.")
        else:
            messagebox.showwarning("Verificación", "Firma inválida.")  # Si la firma es inválida se imprime un mensaje de advertencia
    except Exception as e:
        mostrar_error("Error al verificar firma", e)


def mostrar_error(titulo, error):
    messagebox.showerror(titulo, str(error))
    logging.error(f"{titulo}: {error}")


# Elementos de la interfaz para registro y autenticación
tk.Label(root, text="Usuario", font=("Arial", 12)).pack(pady=5)  # Label es un widget que muestra un texto en la interfaz, en este caso el usuario
tk.Entry(root, textvariable=usuario_var, width=40).pack(pady=5)  # Entry es un widget que permite ingresar texto, en este caso el usuario en la interfaz

tk.Label(root, text="Contraseña", font=("Arial", 12)).pack(pady=5)  # Label es un widget que muestra un texto en la interfaz, en este caso la contraseña
tk.Entry(root, textvariable=contrasena_var, show="*", width=40).pack(pady=5)  # Entry es un widget que permite ingresar texto, en este caso la contraseña en la interfaz

tk.Button(root, text="Registrar", command=registrar, bg="blue", fg="white", width=20).pack(pady=5)  # Button es un widget que permite crear botones en la interfaz, en este caso registrarcon color azul
tk.Button(root, text="Autenticar", command=autenticar, bg="green", fg="white", width=20).pack(pady=5)  # Button es un widget que permite crear botones en la interfaz, en este caso autenticar con color verde
tk.Button(root, text="Borrar Usuario", command=borrar_usuario, bg="red", fg="white", width=20).pack(pady=5)  # Button es un widget que permite crear botones en la interfaz, en este caso borrar usuario con color rojo
tk.Button(root, text="Salir", command=root.quit, bg="yellow", fg="black", width=20).pack(pady=(10, 20))  # Button es un widget que permite crear botones en la interfaz, en este caso salir con color amarillo

# Iniciar la aplicacion
root.mainloop()