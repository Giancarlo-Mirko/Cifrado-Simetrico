import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog


class Aplicacion(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encriptar Archivo")
        self.geometry("400x300")
        self.ruta_archivo_entrada = ""
        self.ruta_carpeta_salida = ""
        self.crear_widgets()

    def crear_widgets(self):
        tk.Label(self, text="Seleccionar archivo de entrada:").pack(pady=10)
        tk.Button(self, text="Buscar",
                  command=self.buscar_archivo_entrada).pack()

        tk.Label(self, text="Seleccionar carpeta de salida:").pack(pady=10)
        tk.Button(self, text="Buscar",
                  command=self.buscar_carpeta_salida).pack()

        tk.Button(self, text="Encriptar",
                  command=self.encriptar_archivo).pack(pady=20)

    def buscar_archivo_entrada(self):
        self.ruta_archivo_entrada = filedialog.askopenfilename(
            filetypes=[("Archivos de texto", "*.txt")])
        tk.Label(self, text=self.ruta_archivo_entrada).pack()

    def buscar_carpeta_salida(self):
        self.ruta_carpeta_salida = filedialog.askdirectory()
        tk.Label(self, text=self.ruta_carpeta_salida).pack()

    def encriptar_archivo(self):
        if not self.ruta_archivo_entrada:
            tk.messagebox.showerror(
                "Error", "Por favor seleccione un archivo de entrada.")
            return

        clave = os.urandom(32)
        iv = os.urandom(16)

        cifrador = Cipher(algorithms.AES(clave), modes.CBC(iv),
                          backend=default_backend())
        encriptador = cifrador.encryptor()

        ruta_archivo_encriptado = os.path.join(
            self.ruta_carpeta_salida, "archivo_encriptado.enc")

        with open(self.ruta_archivo_entrada, "rb") as archivo_entrada, open(ruta_archivo_encriptado, "wb") as archivo_salida:
            rellenador = padding.PKCS7(128).padder()

            # Leer 1024 bytes a la vez
            for chunk in iter(lambda: archivo_entrada.read(1024), b''):
                chunk = encriptador.update(rellenador.update(chunk))

                archivo_salida.write(chunk)

            chunk = encriptador.update(
                rellenador.finalize()) + encriptador.finalize()
            archivo_salida.write(chunk)

        ruta_archivo_clave_iv = os.path.join(
            self.ruta_carpeta_salida, "clave_iv.txt")

        with open(ruta_archivo_clave_iv, "w") as archivo_clave:
            archivo_clave.write("clave: " + str(clave) + "\n")
            archivo_clave.write("iv: " + str(iv))

        tk.messagebox.showinfo("Éxito", "Archivo encriptado exitosamente.")


if __name__ == '__main__':
    app = Aplicacion()
    app.mainloop()
