# **Practica2Ciber**

## **Ejercicio 1**
### Descripción:

Pequeña herramienta de **reconocimiento de dominios** desarrollada en **Python** como práctica de la asignatura "Introducción a Ciberseguridad". El script automatiza varios procesos de **identificación y enumeración** de dominios, tales como la obtención de información WHOIS, la comprobación de filtraciones de correos electrónicos, el escaneo de puertos comunes, y la obtención de servidores **NS** y **MX**.

### Funcionalidades principales:

- **Obtener WHOIS** del dominio (usa `python-whois` si está instalado, o una consulta WHOIS por socket como fallback).
- **Extraer direcciones de correo** encontradas en el WHOIS.
- **Comprobar si el dominio está activo** (HEAD HTTP y fallback por sockets 80/443).
- **Escanear el TOP 10 de puertos comunes** (concurrencia por hilos para velocidad).
- **Obtener registros DNS `NS` y `MX`** (usa `dnspython` si está instalado, o `nslookup` como fallback).
- **Comprobar filtraciones de correos en HaveIBeenPwned (HIBP)** si se encuentran emails (requiere API key).

### Requisitos:

- Python 3.8+
- instalar dependencias (ver `requirements.txt`). Algunas dependencias son opcionales:
  - `python-whois`: Para obtener WHOIS de forma más rica.
  - `dnspython`: Para resolver NS/MX desde Python.
  - `requests`: Usado para HIBP y peticiones HTTP.


## **Ejercicio 2 y 3**
Descritos en el pddf
