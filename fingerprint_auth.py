# fingerprint_auth.py
import ctypes
import logging

def setup_fingerprint_auth():
    """Configura autenticación por huella digital"""
    try:
        # Simula llamada a Windows Hello (requiere permisos elevados)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "whoami", None, None, 0)
        return True
    except Exception as e:
        logging.warning(f"No se pudo configurar autenticación por huella: {e}")
        return False
