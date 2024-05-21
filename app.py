from scapy.all import sniff, IP, TCP
from utils import crear_tabla_alertas, registrar_alerta, enviar_alerta
from config import DESTINATARIO_CORREO

DATABASE = 'ids.db'
ALERT_THRESHOLD = 100  # Número de paquetes desde una IP antes de alertar
SENSITIVE_PORTS = [22, 80, 443]  # Puertos de servicios sensibles

# Conexiones por IP para detección de escaneo de puertos
connections = {}

def packet_callback(packet):
    try:
        if IP in packet and TCP in packet:
            detectar_intrusion(packet)
            descripcion = f"Paquete TCP detectado: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"
            print(f"[+] {descripcion}")
    except Exception as e:
        print(f"[-] Error al procesar el paquete: {e}")

def detectar_intrusion(packet):
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    tcp_sport = packet[TCP].sport
    tcp_dport = packet[TCP].dport
    
    # Registro de conexiones para detectar escaneo de puertos
    if ip_src not in connections:
        connections[ip_src] = []
    connections[ip_src].append(tcp_dport)
    
    # Detectar escaneo de puertos
    if len(connections[ip_src]) > ALERT_THRESHOLD:
        descripcion = f"Posible escaneo de puertos desde {ip_src}"
        registrar_alerta(ip_src, ip_dst, tcp_sport, tcp_dport, descripcion)
        enviar_alerta("Alerta de Intrusión", descripcion, DESTINATARIO_CORREO)
        connections[ip_src] = []  # Reset después de la alerta

    # Detectar conexión a puertos sensibles
    if tcp_dport in SENSITIVE_PORTS:
        descripcion = f"Intento de conexión a puerto sensible {tcp_dport} desde {ip_src}"
        registrar_alerta(ip_src, ip_dst, tcp_sport, tcp_dport, descripcion)
        enviar_alerta("Alerta de Intrusión", descripcion, DESTINATARIO_CORREO)

if __name__ == "__main__":
    crear_tabla_alertas()
    sniff(prn=packet_callback, store=0)
