# Sistema de Detección de Intrusiones (IDS) en Python

Desarrollé un Sistema de Detección de Intrusiones (IDS) utilizando Python, diseñado para monitorear el tráfico de red en tiempo real y alertar sobre posibles amenazas como escaneos de puertos y conexiones a puertos sensibles.

## Características Destacadas:
- **Análisis en Tiempo Real:** Utilicé la biblioteca Scapy para capturar y analizar paquetes de red en tiempo real, permitiendo una detección proactiva de intrusos.
- **Detección de Intrusiones:** Implementé algoritmos para identificar escaneos de puertos y conexiones a puertos sensibles, proporcionando una defensa efectiva contra ataques cibernéticos.
- **Registro y Notificación de Alertas:** Integré una base de datos SQLite para registrar alertas, junto con notificaciones por correo electrónico en caso de actividades sospechosas, garantizando una respuesta rápida ante posibles amenazas.
- **Modularidad y Seguridad:** La estructura modular del código y el almacenamiento seguro de credenciales mediante variables de entorno mejoran la seguridad y la mantenibilidad del proyecto.

## Tecnologías Utilizadas:
- *Python:* Lenguaje de programación principal para el desarrollo del proyecto.
- *Scapy:* Biblioteca de Python para análisis de red.
- *SQLite:* Sistema de gestión de bases de datos para el registro de alertas.
- *smtplib:* Módulo para el envío de correos electrónicos de alerta.
