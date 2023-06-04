import os
import ast
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encriptar y desencriptar archivos")
        self.geometry("400x460")
        self.create_widgets()

    def create_widgets(self):
        self.options_notebook = ttk.Notebook(self)
        self.options_notebook.pack(pady=10)

        # Crear pestañas
        self.encrypt_tab = ttk.Frame(self.options_notebook)
        self.decrypt_tab = ttk.Frame(self.options_notebook)

        # Añadir pestañas al widget Notebook
        self.options_notebook.add(self.encrypt_tab, text="Encriptar")
        self.options_notebook.add(self.decrypt_tab, text="Desencriptar")

        # Llamar a las funciones para crear las opciones de encriptación y desencriptación
        self.create_encrypt_widgets()
        self.create_decrypt_widgets()

    def create_encrypt_widgets(self):
        encrypt_app = EncryptApp(self.encrypt_tab)
        encrypt_app.pack()

    def create_decrypt_widgets(self):
        decrypt_app = DecryptApp(self.decrypt_tab)
        decrypt_app.pack()


class EncryptApp(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.input_file_path = ""
        self.output_folder_path = ""
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Seleccionar archivo:").pack(pady=10)
        tk.Button(self, text="Buscar", command=self.browse_input_file).pack()

        tk.Label(self, text="Seleccionar carpeta:").pack(pady=10)
        tk.Button(self, text="Buscar",
                  command=self.browse_output_folder).pack()

        tk.Button(self, text="Encriptar",
                  command=self.encrypt_file).pack(pady=20)

    def browse_input_file(self):
        self.input_file_path = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.pdf")])
        tk.Label(self, text=self.input_file_path).pack()

    def browse_output_folder(self):
        self.output_folder_path = filedialog.askdirectory()
        tk.Label(self, text=self.output_folder_path).pack()

    def encrypt_file(self):
        if not self.input_file_path:
            tk.messagebox.showerror(
                "Error", "Por favor seleccione un archivo.")
            return

        key = os.urandom(32)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        encrypted_file_path = os.path.join(
            self.output_folder_path, "archivo_encriptado.enc")

        with open(self.input_file_path, "rb") as input_file, open(encrypted_file_path, "wb") as output_file:
            padder = padding.PKCS7(128).padder()

            for chunk in iter(lambda: input_file.read(1024), b''):  # Leer 1024 bytes a la vez
                chunk = encryptor.update(padder.update(chunk))

                output_file.write(chunk)

            chunk = encryptor.update(padder.finalize()) + encryptor.finalize()
            output_file.write(chunk)

        key_iv_file_path = os.path.join(self.output_folder_path, "key_iv.txt")

        with open(key_iv_file_path, "w") as key_file:
            key_file.write("key: " + str(key) + "\n")
            key_file.write("iv: " + str(iv))

        tk.messagebox.showinfo("Success", "Archivo cifrado con éxito.")


class DecryptApp(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.input_file_path = ""
        self.output_folder_path = ""
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Seleccionar archivo encriptado:").pack(pady=10)
        tk.Button(self, text="Buscar",
                  command=self.browse_input_file).pack()

        tk.Label(self, text="Introducir clave (en bytes)").pack(pady=10)
        self.key_entry = tk.Entry(self, width=75)
        self.key_entry.pack(pady=10)

        tk.Label(self, text="Introducir iv (en bytes)").pack(pady=10)
        self.iv_entry = tk.Entry(self, width=75)
        self.iv_entry.pack(pady=10)

        tk.Label(self, text="Seleccionar carpeta de salida:").pack(pady=10)
        tk.Button(self, text="Buscar",
                  command=self.browse_output_folder).pack()

        tk.Button(self, text="Desencriptar",
                  command=self.decrypt_file_wrapper).pack(pady=20)

    def browse_input_file(self):
        self.input_file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Files", "*.enc")])
        tk.Label(self, text=self.input_file_path).pack()

    def browse_output_folder(self):
        self.output_folder_path = filedialog.askdirectory()
        tk.Label(self, text=self.output_folder_path).pack()

    def decrypt_file_wrapper(self):
        key = self.key_entry.get()
        iv = self.iv_entry.get()

        if not key or not iv:
            tk.messagebox.showerror(
                "Error", "Por favor, introduzca tanto la clave como el iv.")
            return

        try:
            # Use ast.literal_eval instead of eval
            key = ast.literal_eval(key)
            # Use ast.literal_eval instead of eval
            iv = ast.literal_eval(iv)
        except:
            tk.messagebox.showerror("Error", "Clave o iv no válidos.")
            return

        input_file_path = self.input_file_path
        output_file_path = os.path.join(
            self.output_folder_path, "archivo_desencriptado.pdf")

        if not input_file_path or not self.output_folder_path:
            tk.messagebox.showerror(
                "Error", "Seleccione un archivo de entrada y una carpeta de salida.")
            return
        try:
            self.decrypt_file(
                key, iv, input_file_path, output_file_path)
            tk.messagebox.showinfo("Success", "Archivo descifrado con éxito.")
        except:
            tk.messagebox.showerror(
                "Error", "El descifrado falló. Verifique la clave, iv y el archivo de entrada.")

    def decrypt_file(self, key, iv, input_file_path, output_file_path):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        with open(input_file_path, "rb") as input_file, open(output_file_path, "wb") as output_file:
            unpadder = padding.PKCS7(128).unpadder()

            for chunk in iter(lambda: input_file.read(1024), b''):
                chunk = decryptor.update(chunk)
                chunk = unpadder.update(chunk)
                output_file.write(chunk)

            chunk = decryptor.finalize()
            chunk += unpadder.finalize()
            output_file.write(chunk)


if __name__ == '__main__':
    app = App()
    app.mainloop()
