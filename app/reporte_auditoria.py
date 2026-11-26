"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Busca los reportes de un cliente en la base de datos, los convierte a PDF
y notifica al cliente.

Corregido en el Laboratorio 1 de Calidad de Software tras la auditoría de
seguridad: consultas parametrizadas, ejecución sin shell con lista blanca,
YAML seguro, hash de contraseñas con sal y secretos fuera del código.
"""

import hashlib
import os
import re
import sqlite3
import subprocess
from pathlib import Path

import yaml

# --- Secretos: se leen de variables de entorno, nunca se escriben en el código ---
# Los valores que estuvieron escritos aquí siguen en el historial de Git:
# se consideran comprometidos y deben rotarse en sus proveedores.
NOTIFICATION_API_KEY = os.environ.get("REPORTAUDIT_NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("REPORTAUDIT_SMTP_PASSWORD", "")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")

# Lista blanca: solo nombres simples terminados en .html; no pueden empezar por "-".
NOMBRE_HTML_VALIDO = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.html$")

# Iteraciones de PBKDF2-HMAC-SHA256 recomendadas por OWASP.
ITERACIONES_PBKDF2 = 600_000


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        # safe_load solo construye datos (dict, list, str, números), nunca objetos de Python.
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente."""
    conexion = sqlite3.connect(ruta_db)
    cursor = conexion.cursor()
    # Consulta parametrizada: el dato viaja separado de la orden SQL.
    query = "SELECT * FROM reportes WHERE cliente = ?"
    cursor.execute(query, (nombre_cliente,))
    resultados = cursor.fetchall()
    conexion.close()
    return resultados


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF usando la utilidad del sistema."""
    # Se valida el valor COMPLETO (no solo Path(...).name): sin barras, sin rutas y sin "-" inicial.
    if not NOMBRE_HTML_VALIDO.fullmatch(nombre_archivo):
        raise ValueError("Nombre de archivo no válido")
    # Prefijo "./": el argumento nunca puede empezar por "-" ni leerse como una opción del programa.
    entrada = os.path.join(".", nombre_archivo)
    salida = entrada + ".pdf"
    try:
        # Lista de argumentos y sin shell: ; & | llegan como texto literal, no como órdenes.
        subprocess.run(["wkhtmltopdf", entrada, salida], check=False)
    except FileNotFoundError:
        print("Aviso: wkhtmltopdf no está instalado; no se generó el PDF.")
    return salida


def hash_password_legacy(password):
    """Genera el hash de una contraseña con PBKDF2-HMAC-SHA256 y sal aleatoria."""
    sal = os.urandom(16)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode(), sal, ITERACIONES_PBKDF2)
    return sal.hex() + ":" + derivado.hex()


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    # Nunca se escribe una credencial en un log, ni siquiera en parte.
    estado = "configurada" if NOTIFICATION_API_KEY else "NO configurada"
    print(f"[NotifyAPI clave {estado}] -> {email}: {mensaje}")
    return True
