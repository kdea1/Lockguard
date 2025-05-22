import hashlib
import keyring
from tempfile import NamedTemporaryFile
import sys
import subprocess
import os
import threading
import asyncio
import tkinter as tk
from tkinter import messagebox, Label, Entry, Button, Text, Scrollbar, ttk, BooleanVar, Checkbutton
from PIL import Image, ImageTk
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError  # Importación añadida para corregir el error
import requests
import json
import sqlite3
from telethon.sessions import StringSession
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import platform
import aiohttp
from collections import defaultdict
import time
from telethon.tl.types import User
import winsound
from plyer import notification
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# Añade estas líneas con las otras importaciones al principio del archivo
import pystray
from PIL import Image, ImageDraw
import threading
from monitor_resources import monitor_system_resources
from fingerprint_auth import setup_fingerprint_auth



# ============================
# 🔰 Configuración inicial
# ============================
SESSION_FILE = "session.txt"
DB_NAME = "threats.db"
INTERFACE = "Wi-Fi"

# ============================
# 🔍 Verificación de Tshark
# ============================
def find_tshark():
    possible_paths = [
        "C:\\Program Files\\Wireshark\\tshark.exe",
        "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark"
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

TSHARK_PATH = find_tshark()
if not TSHARK_PATH:
    messagebox.showerror("Error", "❌ Tshark no está instalado. Instálalo desde https://www.wireshark.org/")
    sys.exit(1)

# ============================
# 🗃 Inicialización de Base de Datos
# ============================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS threats
                (id INTEGER PRIMARY KEY,
                 type TEXT,
                 data TEXT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                (id INTEGER PRIMARY KEY,
                 filename TEXT,
                 hash TEXT UNIQUE,
                 malicious BOOLEAN,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# ============================
# 🖥 Interfaz Gráfica
# ============================
root = tk.Tk()
root.title("LOCKGUARD - Seguridad en Telegram")
root.geometry("800x600")

# Fondo de pantalla
try:
    bg_image = Image.open("background.jpg")  
    bg_image = bg_image.resize((800, 600), Image.Resampling.LANCZOS)
    bg_photo = ImageTk.PhotoImage(bg_image)
    bg_label = Label(root, image=bg_photo)
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)
except Exception as e:
    print(f"Error cargando fondo: {e}")

# Icono de la aplicación
if os.path.exists("gh.ico"):
    root.iconbitmap("gh.ico")

# ============================
# 🔐 Funciones de Credenciales
# ============================
CREDENTIALS_FILE = "credentials.json"

def save_credentials():
    credentials = {
        "api_id": api_id_entry.get(),
        "api_hash": api_hash_entry.get(),
        "phone": phone_entry.get(),
        "virustotal_api": virustotal_entry.get()
    }
    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file)

def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            credentials = json.load(file)
            api_id_entry.insert(0, credentials.get("api_id", ""))
            api_hash_entry.insert(0, credentials.get("api_hash", ""))
            phone_entry.insert(0, credentials.get("phone", ""))
            virustotal_entry.insert(0, credentials.get("virustotal_api", ""))


# ============================
# 🖥️ Funciones para el Icono de Notificación
# ============================
# Variable global para el icono (colócala con tus otras variables globales)
tray_icon = None

def create_tray_image():
    """Crea la imagen para el icono en la bandeja del sistema"""
    # Crear una imagen de 64x64 píxeles
    image = Image.new('RGB', (64, 64), (30, 50, 90))  # Fondo azul oscuro
    dc = ImageDraw.Draw(image)
    
    # Dibujar un cuadrado verde con las iniciales LG
    dc.rectangle((16, 16, 48, 48), fill='green')
    dc.text((20, 20), "LG", fill='white', font=None)  # Texto "LG" (LockGuard)
    
    return image

def on_tray_click(icon, item):
    """Maneja los clics en el menú del icono"""
    if str(item) == "Abrir LOCKGUARD":
        root.deiconify()  # Restaurar la ventana
    elif str(item) == "Minimizar a bandeja":
        root.withdraw()  # Ocultar la ventana
    elif str(item) == "Salir":
        icon.stop()      # Detener el icono
        root.destroy()   # Cerrar la aplicación

def setup_system_tray():
    """Configura el icono en la bandeja del sistema"""
    global tray_icon
    
    # Crear el menú para el icono
    menu = pystray.Menu(
        pystray.MenuItem('Abrir LOCKGUARD', lambda: on_tray_click(tray_icon, "Abrir LOCKGUARD")),
        pystray.MenuItem('Minimizar a bandeja', lambda: on_tray_click(tray_icon, "Minimizar a bandeja")),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem('Salir', lambda: on_tray_click(tray_icon, "Salir"))
    )
    
    # Crear el icono
    tray_icon = pystray.Icon(
        "LOCKGUARD",
        icon=create_tray_image(),
        title="LOCKGUARD - Seguridad en Telegram",
        menu=menu
    )
    
    return tray_icon

def run_tray_icon():
    """Inicia el icono en la bandeja del sistema"""
    global tray_icon
    tray_icon = setup_system_tray()
    tray_icon.run()

def show_tray_notification(title, message, is_warning=False):
    """Muestra una notificación desde el icono"""
    if tray_icon:
        # Cambiar el icono si es una advertencia
        if is_warning:
            warning_img = Image.new('RGB', (64, 64), (90, 30, 30))  # Fondo rojo
            dc = ImageDraw.Draw(warning_img)
            dc.rectangle((16, 16, 48, 48), fill='red')
            dc.text((20, 20), "!", fill='white')
            tray_icon.icon = warning_img
        else:
            tray_icon.icon = create_tray_image()  # Icono normal
            
        # Mostrar la notificación
        tray_icon.notify(message, title)
        
        # Restaurar el icono después de 5 segundos si es una advertencia
        if is_warning:
            threading.Timer(5.0, lambda: setattr(tray_icon, 'icon', create_tray_image())).start()          

# ============================
# 🖨 Componentes de la Interfaz
# ============================
# Campos de entrada
Label(root, text="🔑 API ID:", font=("Arial", 12, "bold")).place(x=10, y=30)
api_id_entry = Entry(root, width=30, show="*")
api_id_entry.place(x=200, y=30)

Label(root, text="🔐 API HASH:", font=("Arial", 12, "bold")).place(x=10, y=70)
api_hash_entry = Entry(root, width=30, show="*")
api_hash_entry.place(x=200, y=70)

Label(root, text="📱 Número de Telegram:", font=("Arial", 12, "bold")).place(x=10, y=110)
phone_entry = Entry(root, width=30, show="*")
phone_entry.place(x=200, y=110)

Label(root, text="🦠 API Key VirusTotal:", font=("Arial", 12, "bold")).place(x=10, y=150)
virustotal_entry = Entry(root, width=30, show="*")
virustotal_entry.place(x=200, y=150)

# Botón de visibilidad
show_data = BooleanVar(value=False)
def toggle_visibility():
    show = "" if show_data.get() else "*"
    api_id_entry.config(show=show)
    api_hash_entry.config(show=show)
    phone_entry.config(show=show)
    virustotal_entry.config(show=show)
Checkbutton(root, text="Mostrar datos", variable=show_data, command=toggle_visibility).place(x=200, y=180)

# Selección de interfaz de red
Label(root, text="🌍 Interfaz de Red:", font=("Arial", 12, "bold")).place(x=10, y=220)

def get_tshark_interfaces():
    try:
        result = subprocess.run([TSHARK_PATH, "-D"], capture_output=True, text=True)
        interfaces = [line.split(". ")[1] for line in result.stdout.splitlines()]
        return interfaces
    except Exception as e:
        messagebox.showerror("Error", f"⚠ No se pudieron obtener las interfaces: {e}")
        return []

interfaces = get_tshark_interfaces()
interface_combobox = ttk.Combobox(root, values=interfaces, width=27)
interface_combobox.place(x=200, y=220)
if interfaces:
    interface_combobox.current(0)

# Área de resultados
Label(root, text="📋 Resultados:", font=("Arial", 12, "bold")).place(x=50, y=260)
output_text = Text(root, width=80, height=15, wrap="word", bg="black", fg="lime", font=("Courier", 10))
output_text.place(x=50, y=290)

scrollbar = Scrollbar(root, command=output_text.yview)
scrollbar.place(x=730, y=290, height=240)
output_text.config(yscrollcommand=scrollbar.set)

def log_result(message):
    output_text.insert(tk.END, message + "\n")
    output_text.see(tk.END)

# ============================
# 🛡 Funciones de Seguridad
# ============================
client = None
verification_code = None
PHONE_NUMBER = None
failed_attempts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
BLOCK_TIME = 600
MAX_ATTEMPTS = 5

class AsyncThread(threading.Thread):
    def __init__(self, coro):
        super().__init__(daemon=True)
        self.coro = coro
        self.result = None
        self.error = None

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.result = loop.run_until_complete(self.coro)
        except Exception as e:
            self.error = e
            root.after(0, lambda: messagebox.showerror("Error crítico", f"{str(e)}\n\nRevisa tus credenciales y conexión."))
        finally:
            loop.close()

async def get_code():
    code_event = asyncio.Event()
    code = [None]  # Usamos lista para modificar en closure
    
    def show_code_dialog():
        code_window = tk.Toplevel(root)
        code_window.title("Verificación de Código")
        code_window.geometry("300x150")
        code_window.iconbitmap("code_icon.ico")  # ← Ícono para esta ventana
        code_window.grab_set()
        
        tk.Label(code_window, text="Ingrese el código de verificación de 5 dígitos:", font=("Arial", 12)).pack(pady=10)
        entry = tk.Entry(code_window, font=("Arial", 14), width=10)
        entry.pack(pady=5)
        
        def on_submit():
            code[0] = entry.get()
            code_window.destroy()
            code_event.set()
        
        tk.Button(code_window, text="Validar", command=on_submit, bg="#4CAF50", fg="white").pack(pady=10)
        code_window.protocol("WM_DELETE_WINDOW", lambda: None)  # Bloquear cierre
        
    root.after(0, show_code_dialog)
    await code_event.wait()
    return code[0]


async def check_link_safety(link):
    vt_api = virustotal_entry.get().strip()
    if not vt_api:
        root.after(0, lambda: log_result("⚠ No se ha ingresado una clave de API de VirusTotal."))
        return

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": vt_api},
                data={"url": link}
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    
                    with sqlite3.connect(DB_NAME) as conn:
                        conn.execute("INSERT INTO threats (type, data) VALUES (?,?)", 
                                   ("malicious_link" if malicious > 0 else "safe_link", link))
                    
                    if malicious > 0:
                        root.after(0, lambda: winsound.Beep(1000, 500))
                        root.after(0, lambda: notification.notify(
                            title="Alerta LOCKGUARD",
                            message="Enlace malicioso detectado!",
                            timeout=10
                        ))
                        root.after(0, lambda: log_result(f"🚨 Enlace peligroso! Detecciones: {malicious}"))
                    else:
                        root.after(0, lambda: log_result("✅ Enlace seguro verificado"))

                else:
                    root.after(0, lambda: log_result(f"⚠ Error en VirusTotal: {response.status}"))

    except Exception as e:
        root.after(0, lambda: log_result(f"⚠ Error con VirusTotal: {str(e)}"))

async def start_monitoring():
    @client.on(events.NewMessage)
    async def handler(event):
        sender = await event.get_sender()
        if isinstance(sender, User):
            msg = f"📩 Mensaje de {sender.username or 'Desconocido'}: {event.text}"
            root.after(0, lambda: log_result(msg))
            if 'http' in event.text.lower():
                await check_link_safety(event.text)

    async def monitor_traffic():
        tshark_cmd = [TSHARK_PATH, "-i", INTERFACE, "-Y", "ip.dst == 149.154.167.50"]
        process = await asyncio.create_subprocess_exec(*tshark_cmd, stdout=asyncio.subprocess.PIPE)
        async for line in process.stdout:
            root.after(0, lambda: log_result(f"🌐 Tráfico detectado: {line.decode().strip()}"))

    await asyncio.gather(
        client.run_until_disconnected(),
        monitor_traffic()
    )

def get_2fa_password():
    """Obtiene la contraseña 2FA del almacén seguro"""
    return keyring.get_password("LOCKGUARD_2FA", "telegram")

def save_2fa_password(password):
    """Guarda la contraseña 2FA de forma segura"""
    keyring.set_password("LOCKGUARD_2FA", "telegram", password)

async def get_2fa_from_gui():
    """Ventana para ingresar la contraseña 2FA"""
    code_event = asyncio.Event()
    password = [None]
    
    def show_2fa_dialog():
        window = tk.Toplevel(root)
        window.title("Verificación en Dos Pasos")
        window.geometry("300x150")
        window.iconbitmap("2fa_icon.ico")  # Ícono solo para esta ventana

        tk.Label(window, text="🔒 Ingrese su contraseña 2FA:", font=("Arial", 12)).pack(pady=10)
        entry = tk.Entry(window, show="*", font=("Arial", 12))
        entry.pack(pady=5)
        
        def submit():
            password[0] = entry.get()
            window.destroy()
            code_event.set()
        
        tk.Button(window, text="Validar", command=submit, bg="#4CAF50", fg="white").pack(pady=10)
    
    root.after(0, show_2fa_dialog)
    await code_event.wait()
    return password[0]

async def get_telegram_code_from_gui():
    """Ventana para ingresar el código de Telegram"""
    code_event = asyncio.Event()
    code = [None]

    def show_code_dialog():
        window = tk.Toplevel(root)
        window.title("Código de Telegram")
        window.geometry("300x150")
        window.iconbitmap("telegram_icon.ico")  # Ícono solo para esta ventana

        tk.Label(window, text="📨 Ingrese el código de Telegram:", font=("Arial", 12)).pack(pady=10)
        entry = tk.Entry(window, font=("Arial", 12))
        entry.pack(pady=5)

        def submit():
            code[0] = entry.get()
            window.destroy()
            code_event.set()

        tk.Button(window, text="Enviar", command=submit, bg="#2196F3", fg="white").pack(pady=10)

    root.after(0, show_code_dialog)
    await code_event.wait()
    return code[0]

async def authenticate_and_monitor(resend=False):
    global client
    
    try:
        api_id = api_id_entry.get().strip()
        api_hash = api_hash_entry.get().strip()
        phone = phone_entry.get().strip()

        # Validación de campos
        if not all([api_id, api_hash, phone]):
            root.after(0, lambda: messagebox.showerror("Error", "❌ Todos los campos son obligatorios"))
            return

        if not api_id.isdigit():
            root.after(0, lambda: messagebox.showerror("Error", "❌ El API ID debe ser numérico"))
            return

        # Crear cliente
        client = TelegramClient(
            StringSession(),
            int(api_id),
            api_hash,
            device_model="LOCKGUARD Security",
            system_version="1.0",
            app_version="2.0"
        )

        await client.connect()

        if not await client.is_user_authorized():
            # Enviar código
            if resend:
                await client.send_code_request(phone, force_sms=True)
                root.after(0, lambda: messagebox.showinfo("Éxito", "📲 SMS de verificación reenviado"))
            else:
                await client.send_code_request(phone)
                root.after(0, lambda: messagebox.showinfo("Éxito", "📩 Código enviado al dispositivo vinculado"))

            # Obtener código
            code = await get_code()
            if not code or len(code) != 5:
                root.after(0, lambda: messagebox.showerror("Error", "❌ Código inválido"))
                return

            # Verificar 2FA si es necesario
            try:
                await client.sign_in(phone, code)
            except SessionPasswordNeededError:
                password = await get_2fa_from_gui()
                if password:
                    await client.sign_in(password=password)
                    save_2fa_password(password)
                else:
                    raise Exception("Se requiere 2FA")

            # Guardar sesión
            with open(SESSION_FILE, "w") as f:
                f.write(client.session.save())

        # Iniciar monitoreo
        root.after(0, lambda: log_result("\n🔥 Monitoreo iniciado correctamente\n"))
        await start_monitoring()

    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        if "A wait of" in error_msg:
            wait_time = error_msg.split("A wait of ")[1].split(" ")[0]
            error_msg += f"\n\n⏳ Debes esperar {wait_time} segundos antes de reintentar."
        root.after(0, lambda: messagebox.showerror("Error de Autenticación", error_msg))
    finally:
        if client:
            await client.disconnect()

def bloquear_ip(ip):
    sistema = platform.system()
    if sistema == "Windows":
        os.system(f'netsh advfirewall firewall add rule name="Bloqueo {ip}" dir=in action=block remoteip={ip}')
    elif sistema == "Linux":
        os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
    else:
        root.after(0, lambda: log_result("⚠ Sistema no compatible para bloqueo de IP."))
        return
    root.after(0, lambda: log_result(f"🚫 IP {ip} bloqueada en {sistema}."))

def run_security():
    if not all([api_id_entry.get(), api_hash_entry.get(), phone_entry.get()]):
        messagebox.showerror("Error", "⚠️ Completa todos los campos requeridos")
        return
    
    start_button.config(state=tk.DISABLED, bg="gray")
    resend_button.config(state=tk.DISABLED, bg="gray")
    
    def reset_buttons():
        start_button.config(state=tk.NORMAL, bg="green")
        resend_button.config(state=tk.NORMAL, bg="blue")
    
    thread = AsyncThread(authenticate_and_monitor())
    thread.start()
    
    # Verificar estado cada 500ms
    def check_thread():
        if thread.is_alive():
            root.after(500, check_thread)
        else:
            reset_buttons()
            if thread.error:
                log_result(f"\n❌ Error: {thread.error}")
    
    check_thread()

def resend_verification_code():
    if not phone_entry.get().strip():
        messagebox.showerror("Error", "⚠️ Ingresa tu número de teléfono primero")
        return
    
    resend_button.config(state=tk.DISABLED, bg="gray")
    
    def reset_button():
        resend_button.config(state=tk.NORMAL, bg="blue")
    
    thread = AsyncThread(authenticate_and_monitor(resend=True))
    thread.start()
    
    def check_thread():
        if thread.is_alive():
            root.after(500, check_thread)
        else:
            reset_button()
    
    check_thread()

# ============================
# 📊 Funciones de Estadísticas
# ============================
def show_stats():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT type, COUNT(*) FROM threats GROUP BY type")
    data = c.fetchall()
    conn.close()

    fig = plt.Figure(figsize=(6,4))
    ax = fig.add_subplot(111)
    ax.bar([x[0] for x in data], [x[1] for x in data])
    ax.set_title("Estadísticas de Amenazas")
    
    stats_window = tk.Toplevel(root)
    canvas = FigureCanvasTkAgg(fig, master=stats_window)
    canvas.draw()
    canvas.get_tk_widget().pack()

# ============================
# 🎛 Botones Finales
# ============================
start_button = Button(root, text="🚀 Iniciar Seguridad", font=("Arial", 12, "bold"), bg="green", fg="white", command=run_security)
start_button.place(x=200, y=550)

resend_button = Button(root, text="🔄 Reenviar Código", font=("Arial", 12, "bold"), bg="blue", fg="white", command=resend_verification_code)
resend_button.place(x=400, y=550)

Button(root, text="📊 Estadísticas", font=("Arial", 12, "bold"), bg="purple", fg="white", command=show_stats).place(x=600, y=550)

remember_button = Button(root, text="💾 Recordar", font=("Arial", 12, "bold"), bg="gray", fg="white", command=save_credentials)
remember_button.place(x=80, y=550)

Button(root, text="🛡️ Configurar 2FA", font=("Arial", 10), bg="#FF5722", fg="white",
      command=lambda: AsyncThread(get_2fa_from_gui()).start()).place(x=600, y=190)


def show_about():
    about_text = """
    🛡️ LOCKGUARD - Sistema Avanzado de Seguridad para Telegram
    
    🌟 Versión: 2.1.0
    👨‍💻 Autor: Ernesto López
    🔗 GitHub: github.com/ernesto-lopez/LOCKGUARD
    🌍 Comunidad: HackingTeam | @SeguridadTI
    
    🔍 CARACTERÍSTICAS PRINCIPALES:
    
    🔒 Protección Integral:
    ✅ Monitoreo de tráfico en tiempo real con Wireshark/tshark
    ✅ Verificación de enlaces con VirusTotal API v3
    ✅ Detección de patrones de tráfico sospechosos
    ✅ Bloqueo automático de IPs maliciosas
    
    📊 Sistema de Alertas:
    🔊 Notificaciones sonoras personalizables
    📨 Alertas visuales en tiempo real
    📈 Registro histórico en base de datos SQLite
    📊 Panel de estadísticas integrado
    
    🔐 Autenticación Segura:
    ⚙️ Soporte para verificación en dos pasos (2FA)
    🔄 Reenvío seguro de códigos de verificación
    💾 Almacenamiento cifrado de credenciales
    
    🖥️ Interfaz Avanzada:
    🎨 Temas personalizables (claro/oscuro)
    📱 Diseño responsive adaptable
    🔄 Actualizaciones automáticas
    """
    
    messagebox.showinfo(
        "LOCKGUARD | Seguridad Avanzada para Telegram",
        about_text
    )
about_button = Button(root, text="ℹ Acerca de", font=("Arial", 12, "bold"), bg="blue", fg="white", command=show_about)
about_button.place(x=600, y=120)

load_credentials()
init_db()  # Asegurarse que la base de datos está inicializada

# ============================
# 🏁 Iniciar Aplicación
# ============================
# ============================
# 🏁 Iniciar Aplicación
# ============================
if __name__ == "__main__":
    # Configurar el comportamiento al cerrar la ventana
    root.protocol('WM_DELETE_WINDOW', lambda: root.withdraw())

    # Iniciar el icono en un hilo separado
    try:
        tray_thread = threading.Thread(target=run_tray_icon, daemon=True)
        tray_thread.start()
        
        # Mostrar notificación de inicio - CORREGIDO: usar show_tray_notification
        root.after(1000, lambda: show_tray_notification(
            "LOCKGUARD Iniciado", 
            "El sistema de seguridad está activo"
        ))
    except Exception as e:
        print(f"No se pudo iniciar el system tray: {e}")
    
    root.mainloop()
