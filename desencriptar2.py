import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import ast  # Importa el módulo 'ast'


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Desencriptar Archivo")
        self.geometry("400x410")
        self.ruta_archivo_entrada = ""
        self.ruta_carpeta_salida = ""
        self.crear_widgets()

    def crear_widgets(self):
        tk.Label(self, text="Seleccionar archivo encriptado:").pack(pady=10)
        tk.Button(self, text="Buscar",
                  command=self.examinar_archivo_entrada).pack()

        self.entrada_clave = tk.Entry(self, width=60)
        self.entrada_clave.pack(pady=10)
        tk.Label(self, text="Introducir clave (en bytes)").pack()

        self.entrada_iv = tk.Entry(self, width=60)
        self.entrada_iv.pack(pady=10)
        tk.Label(self, text="Introducir iv (en bytes)").pack()

        tk.Label(self, text="Seleccionar carpeta de salida:").pack(pady=10)
        tk.Button(self, text="Buscar",
                  command=self.examinar_carpeta_salida).pack()

        # llama a la función "desencriptar_archivo_wrapper()" en lugar de "desencriptar_archivo"
        tk.Button(self, text="Desencriptar",
                  command=self.desencriptar_archivo_wrapper).pack(pady=20)

    def examinar_archivo_entrada(self):
        self.ruta_archivo_entrada = filedialog.askopenfilename(
            filetypes=[("Archivos Encriptados", "*.enc")])
        tk.Label(self, text=self.ruta_archivo_entrada).pack()

    def examinar_carpeta_salida(self):
        self.ruta_carpeta_salida = filedialog.askdirectory()
        tk.Label(self, text=self.ruta_carpeta_salida).pack()

    def desencriptar_archivo(self, clave, iv, ruta_archivo_entrada, ruta_archivo_salida):
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        with open(ruta_archivo_entrada, "rb") as archivo_entrada, open(ruta_archivo_salida, "wb") as archivo_salida:
            unpadder = padding.PKCS7(128).unpadder()
            data = b""

            # Leer 1024 bytes a la vez
            for chunk in iter(lambda: archivo_entrada.read(1024), b''):
                data += decryptor.update(chunk)

            data += decryptor.finalize()
            data = unpadder.update(data) + unpadder.finalize()
            archivo_salida.write(data)

    def desencriptar_archivo_wrapper(self):
        clave = self.entrada_clave.get()
        iv = self.entrada_iv.get()

        if not clave or not iv:
            messagebox.showerror(
                "Error", "Por favor, introduzca tanto la clave como el iv.")
            return

        try:
            # Usa ast.literal_eval en lugar de eval
            clave = ast.literal_eval(clave)
            # Usa ast.literal_eval en lugar de eval
            iv = ast.literal_eval(iv)
        except:
            messagebox.showerror("Error", "Clave o iv no válidos.")
            return

        ruta_archivo_entrada = self.ruta_archivo_entrada
        ruta_archivo_salida = os.path.join(
            self.ruta_carpeta_salida, "archivo_desencriptado.txt")

        if not ruta_archivo_entrada or not self.ruta_carpeta_salida:
            messagebox.showerror(
                "Error", "Seleccione un archivo de entrada y una carpeta de salida..")
            return
        try:
            self.desencriptar_archivo(
                clave, iv, ruta_archivo_entrada, ruta_archivo_salida)
            messagebox.showinfo("éxito", "Archivo descifrado con éxito.")
        except:
            messagebox.showerror(
                "Error", "El descifrado falló. Verifique la clave, iv y el archivo de entrada.")


if __name__ == '__main__':
    app = App()
    app.mainloop()
