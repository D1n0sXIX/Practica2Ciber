import os
import requests
import time
import re
import socket
import argparse
import subprocess
import concurrent.futures
from typing import List, Dict, Optional

def obtener_api_key():
    """Función para obtener la API Key de HIBP."""
    api_key = os.getenv("HIBP_API_KEY")
    
    # Si la API Key no está configurada como variable de entorno, preguntar al usuario
    if not api_key:
        print("[!] API Key no encontrada en variables de entorno [!]")
        print("[!] Por favor, ingrese su API Key de HaveIBeenPwned [!]")
        api_key = input("Ingrese su HIBP API Key: ")
        
    if api_key:
        return api_key
    else:
        print("[!] No se dio ninguna API Key [!]")
        return None

def comprFiltracion(correos):
    """Comprobar filtraciones de los correos proporcionados usando la API de HIBP."""
    filtraciones = {}  # Diccionario para almacenar resultados
    api_key = obtener_api_key()  # Llamada para obtener la API Key
    
    # Si no hay correos, retornar vacío
    if not correos:
        return filtraciones

    # Si no hay API key, se retorna el diccionario vacío
    if not api_key:
        print("[!] No se encontró la API Key [!]")
        for correo in correos:
            filtraciones[correo] = "No comprobado (sin API Key)"
        return filtraciones

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "Ejercicio1Script",
        "Accept": "application/json"
    }

    def _get_with_backoff(url, headers, max_retries=4):
        delay = 1.0
        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=10)
            except requests.exceptions.RequestException as e:
                resp = None
                last_exc = e
            else:
                last_exc = None

            if resp is not None and resp.status_code not in (429,):
                return resp

            # Si fue 429 o excepción, esperar y reintentar
            if attempt < max_retries:
                time.sleep(delay)
                delay *= 2
            else:
                if last_exc:
                    raise last_exc
                return resp

    for correo in correos:
        print(f"[-] Comprobando filtración para: {correo} ...")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}"
        try:
            response = _get_with_backoff(url, headers)
            if response is None:
                filtraciones[correo] = "Error: sin respuesta (excepción)"
                continue

            if response.status_code == 200:
                try:
                    breaches = response.json()
                    filtraciones[correo] = [b.get("Name") for b in breaches]
                except ValueError:
                    filtraciones[correo] = "Error al procesar respuesta JSON"
            elif response.status_code == 404:
                filtraciones[correo] = []
            elif response.status_code == 401:
                filtraciones[correo] = "Error: API key inválida (401)"
                print("[!] Error 401: API key inválida.")
            else:
                filtraciones[correo] = f"Error HTTP {response.status_code}"
        except Exception as e:
            filtraciones[correo] = f"Error: {e}"

        time.sleep(1.6)  # HIBP recomienda 1.6s entre peticiones

    return filtraciones


def obtener_whois(dominio: str) -> Optional[str]:
    """Intentar obtener WHOIS del dominio. Retorna texto raw o None si no disponible.

    Requiere `python-whois` (módulo `whois`). Si no está instalado devuelve None y muestra
    una sugerencia para instalarlo.
    """
    # Preferir módulo 'whois' si está disponible
    try:
        import whois  # type: ignore
    except Exception:
        whois = None

    if whois:
        try:
            w = whois.whois(dominio)
            return str(w)
        except Exception as e:
            print(f"[!] Error obteniendo WHOIS con python-whois: {e}")

    # Fallback: realizar consulta WHOIS por socket a whois.iana.org para obtener servidor referenciado
    def _whois_query_socket(domain: str) -> Optional[str]:
        try:
            with socket.create_connection(("whois.iana.org", 43), timeout=10) as s:
                s.sendall((domain + "\r\n").encode('utf-8'))
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            text = data.decode('utf-8', errors='replace')
            # buscar referencia a servidor WHOIS
            m = re.search(r"refer:\s*(\S+)", text, re.IGNORECASE)
            whois_server = m.group(1).strip() if m else None
            if whois_server:
                try:
                    with socket.create_connection((whois_server, 43), timeout=10) as s2:
                        s2.sendall((domain + "\r\n").encode('utf-8'))
                        data2 = b""
                        while True:
                            chunk = s2.recv(4096)
                            if not chunk:
                                break
                            data2 += chunk
                    return data2.decode('utf-8', errors='replace')
                except Exception:
                    return text
            return text
        except Exception as e:
            print(f"[!] Error WHOIS socket: {e}")
            return None

    return _whois_query_socket(dominio)


def extraer_correos_whois(whois_text: str) -> List[str]:
    """Extraer direcciones de correo del texto WHOIS usando regex.
    Devuelve lista sin duplicados.
    """
    if not whois_text:
        return []
    pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    encontrados = re.findall(pattern, whois_text)
    # normalizar a minúsculas y eliminar duplicados
    return sorted({e.lower() for e in encontrados})


def comprobar_dominio_vivo(dominio: str, timeout: float = 5.0) -> bool:
    """Comprobar si el dominio responde (intento HEAD HTTP). Si falla, intentar socket a 80/443."""
    try:
        resp = requests.head(f"http://{dominio}", timeout=timeout, allow_redirects=True)
        if resp.status_code < 500:
            return True
    except Exception:
        pass

    # Intento a sockets en 80/443
    for port in (80, 443):
        try:
            with socket.create_connection((dominio, port), timeout=timeout):
                return True
        except Exception:
            continue
    return False


def scan_top_ports(dominio: str, ports: List[int] = None, timeout: float = 1.0) -> List[int]:
    """Escanear puertos TCP (TOP10 por defecto). Devuelve lista de puertos abiertos."""
    if ports is None:
        ports = [80, 443, 22, 21, 25, 3389, 3306, 8080, 53, 110]

    abiertos: List[int] = []
    try:
        ip = socket.gethostbyname(dominio)
    except Exception:
        ip = None

    target = ip if ip else dominio

    def _check_port(p: int) -> Optional[int]:
        try:
            with socket.create_connection((target, p), timeout=timeout):
                return p
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(ports))) as ex:
        futures = {ex.submit(_check_port, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                abiertos.append(res)

    return sorted(abiertos)


def obtener_dns_ns_mx(dominio: str) -> Dict[str, List[str]]:
    """Intentar obtener registros NS y MX usando dnspython. Si no disponible, devolver listas vacías."""
    result = {"NS": [], "MX": []}
    try:
        import dns.resolver  # type: ignore
    except Exception:
        dns = None

    if dns:
        try:
            answers_ns = dns.resolver.resolve(dominio, 'NS')
            result['NS'] = sorted([rdata.to_text().rstrip('.') for rdata in answers_ns])
        except Exception:
            result['NS'] = []

        try:
            answers_mx = dns.resolver.resolve(dominio, 'MX')
            result['MX'] = sorted([r.exchange.to_text().rstrip('.') for r in answers_mx])
        except Exception:
            result['MX'] = []

        return result

    # Fallback: usar nslookup y parsear salida
    def _nslookup(record_type: str) -> List[str]:
        try:
            completed = subprocess.run(["nslookup", "-type=" + record_type, dominio], capture_output=True, text=True, timeout=8)
            out = completed.stdout.splitlines()
            found: List[str] = []
            for line in out:
                # patrones comunes: 'nameserver = ns1.example.com' o 'mail exchanger = 10 mail.example.com'
                m_ns = re.search(r"nameserver\s*=\s*(\S+)", line, re.IGNORECASE)
                if m_ns:
                    found.append(m_ns.group(1).rstrip('.'))
                    continue
                m_mx = re.search(r"mail exchanger \=\s*(?:\d+\s*)?(\S+)", line, re.IGNORECASE)
                if m_mx:
                    found.append(m_mx.group(1).rstrip('.'))
            return sorted(set(found))
        except Exception:
            return []

    result['NS'] = _nslookup('ns')
    result['MX'] = _nslookup('mx')
    return result


def imprimir_resultados(dominio: str, whois_text: Optional[str], correos: List[str], filtraciones: Dict[str, object], vivo: bool, puertos: List[int], dns_info: Dict[str, List[str]]):
    print(f"\n== Resultado para: {dominio} ==")
    print(f"WHOIS disponible: {'sí' if whois_text else 'no'}")
    if correos:
        print("Correos extraídos:")
        for c in correos:
            print(f"  - {c}")
    else:
        print("No se encontraron correos en WHOIS.")

    print("\nFiltraciones (HaveIBeenPwned):")
    if filtraciones:
        for correo, info in filtraciones.items():
            print(f"- {correo}: {info}")
    else:
        print("  (No se comprobaron filtraciones)")

    print(f"\nDominio activo: {'sí' if vivo else 'no'}")
    print("Puertos abiertos:")
    if puertos:
        for p in puertos:
            print(f"  - {p}/tcp")
    else:
        print("  Ninguno de los puertos TOP10 parece abierto.")

    print("\nServidores NS:")
    for ns in dns_info.get('NS', []):
        print(f"  - {ns}")
    print("Servidores MX:")
    for mx in dns_info.get('MX', []):
        print(f"  - {mx}")


def main():
    parser = argparse.ArgumentParser(description='Herramienta básica de reconocimiento de dominio')
    parser.add_argument('dominio', help='Dominio a analizar (ej: example.com)')
    parser.add_argument('--hibp-api-key', help='API key de HaveIBeenPwned (opcional)')
    args = parser.parse_args()

    dominio = args.dominio
    if args.hibp_api_key:
        os.environ['HIBP_API_KEY'] = args.hibp_api_key

    whois_text = obtener_whois(dominio)
    correos = extraer_correos_whois(whois_text) if whois_text else []
    filtraciones = {}
    if correos:
        filtraciones = comprFiltracion(correos)

    vivo = comprobar_dominio_vivo(dominio)
    puertos = scan_top_ports(dominio)
    dns_info = obtener_dns_ns_mx(dominio)

    imprimir_resultados(dominio, whois_text, correos, filtraciones, vivo, puertos, dns_info)


if __name__ == '__main__':
    main()

"""
Ejemplo de ejecución (comentado para evitar errores de sintaxis):
[-] Obteniendo WHOIS de example.com...
[-] Extrayendo correos de WHOIS...
[-] Comprobando filtración para: ejemplo@example.com
[-] El correo ejemplo@example.com está involucrado en las siguientes brechas:
    - LinkedIn Breach
    - Adobe Breach
[-] Comprobando si el dominio example.com está activo...
[-] Escaneando puertos...
[-] Puertos abiertos:
    - 80/tcp
    - 443/tcp
    - 22/tcp
[-] Servidores NS:
    - ns1.example.com
    - ns2.example.com
[-] Servidores MX:
    - mail.example.com
"""
