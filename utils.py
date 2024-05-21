import sqlite3
from email.mime.text import MIMEText
import smtplib
from .config import REMITENTE_CORREO, CONTRASEÑA_CORREO

DATABASE = 'ids.db'

def conectar_db():
    try:
        return sqlite3.connect(DATABASE)
    except sqlite3.Error as e:
        print(f"Error al conectar a la base de datos: {e}")

def crear_tabla_alertas():
    db = conectar_db()
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS alertas (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_origen TEXT,
                        ip_destino TEXT,
                        puerto_origen INTEGER,
                        puerto_destino INTEGER,
                        descripcion TEXT,
                        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
    db.commit()
    db.close()

def registrar_alerta(ip_origen, ip_destino, puerto_origen, puerto_destino, descripcion):
    try:
        db = conectar_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO alertas (ip_origen, ip_destino, puerto_origen, puerto_destino, descripcion) VALUES (?, ?, ?, ?, ?)",
                       (ip_origen, ip_destino, puerto_origen, puerto_destino, descripcion))
        db.commit()
        db.close()
    except sqlite3.Error as e:
        print(f"Error al registrar alerta en la base de datos: {e}")

def enviar_alerta(asunto, mensaje, destinatario):
    remitente = REMITENTE_CORREO
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(remitente, CONTRASEÑA_CORREO)
        msg = MIMEText(mensaje)
        msg['Subject'] = asunto
        msg['From'] = remitente
        msg['To'] = destinatario
        server.sendmail(remitente, [destinatario], msg.as_string())
        server.quit()
        print("[+] Alerta enviada correctamente")
    except Exception as e:
        print(f"[-] Error al enviar alerta: {e}")
