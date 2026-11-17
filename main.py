import sys
import re
import argparse
import serial.tools.list_ports
from FlipperNested.main import FlipperNested
from FlipperNested.bridge import FlipperBridge

# --- COLORES PARA LA TERMINAL ---
C_GREEN = '\033[92m'
C_CYAN = '\033[96m'
C_RED = '\033[91m'
C_YELLOW = '\033[93m'
C_RESET = '\033[0m'

class PrettyPrinter:
    """Intercepta y embellece los mensajes de texto, almacenando memoria del contexto"""
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout
        self.buffer = ""
        self.current_k_type = "?"
        self.current_sec = "?"

    def write(self, text):
        # Almacenamos el texto hasta encontrar un salto de línea
        self.buffer += text
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            self.process_line(line)

    def process_line(self, msg):
        msg = msg.strip()
        if not msg:
            return

        if msg.startswith("Recovering key type"):
            # Extraemos los datos: "Recovering key type A, sector 0"
            match = re.search(r"type\s+([A-B]),\s+sector\s+(\d+)", msg)
            if match:
                self.current_k_type = match.group(1)
                self.current_sec = match.group(2)
                self.original_stdout.write(f"   {C_CYAN}➜{C_RESET} Analizando Sector {self.current_sec:>2} (Buscando Llave {self.current_k_type})... ")
                self.original_stdout.flush()
            else:
                self.original_stdout.write(f"{msg}\n")
                
        elif msg.startswith("Found"):
            if "Found 0" in msg or "[]" in msg:
                self.original_stdout.write(f"{C_YELLOW}Intento fallido (Requiere ataque Hardnested){C_RESET}\n")
            else:
                # Limpiamos el formato "Found 1 key(s): ['0105afbecd12']"
                llaves_str = msg.split(":", 1)[-1].strip()
                llaves_limpias = llaves_str.replace("[", "").replace("]", "").replace("'", "").replace(" ", "").upper()
                
                # Imprimimos la llave asociándola con su tipo (A o B)
                self.original_stdout.write(f"{C_GREEN}¡ÉXITO! {C_RESET}La Llave {self.current_k_type} es: {C_GREEN}{llaves_limpias}{C_RESET}\n")
                
        elif "Failed to find keys" in msg:
            self.original_stdout.write(f"   {C_RED}✘ Falló la extracción para este sector.{C_RESET}\n")
        elif "Stopping" in msg:
            self.original_stdout.write(f"\n{C_RED}[!] Deteniendo proceso...{C_RESET}\n")
        else:
            # Ocultamos la basura de procesamiento interno
            pass

    def flush(self):
        self.original_stdout.flush()

def detect_flipper_port():
    """Escanea los puertos USB activos buscando la firma del Flipper Zero"""
    ports = serial.tools.list_ports.comports()
    for port in ports:
        if port.description and "Flipper" in port.description:
            return port.device
        if port.manufacturer and "Flipper" in port.manufacturer:
            return port.device
        if port.vid == 0x0483 and port.pid == 0x5740:
            return port.device
    return None

def format_momentum_to_v3(raw_text):
    """Convierte el formato crudo de Momentum al formato estricto V3"""
    formatted_lines = [
        "Filetype: Flipper Nested Nonce Manifest File",
        "Version: 3",
        "Note:"
    ]
    for line in raw_text.splitlines():
        line = line.strip()
        if line.startswith("Sec "):
            p = line.split()
            new_line = f"Nested: Key {p[3]} cuid 0x{p[5]} nt0 0x{p[7]} ks0 0x{p[9]} par0 {p[11]} nt1 0x{p[13]} ks1 0x{p[15]} par1 {p[17]} sec {p[1]}"
            formatted_lines.append(new_line)
    return "\n".join(formatted_lines)

def main():
    parser = argparse.ArgumentParser(description="Auto Flipper Nested Cracker")
    parser.add_argument("-p", "--port", required=False, help="Puerto COM (ej. /dev/ttyACM0). Se autodetectará si se omite.")
    parser.add_argument("-f", "--file", default="/ext/nfc/.nested.log", help="Ruta del archivo en el Flipper")
    args = parser.parse_args()

    port_to_use = args.port
    if not port_to_use:
        print("[*] Buscando Flipper Zero conectado por USB...")
        port_to_use = detect_flipper_port()
        if port_to_use:
            print(f"[+] ¡Flipper encontrado automáticamente en: {C_GREEN}{port_to_use}{C_RESET}!")
        else:
            print(f"{C_RED}[!] No se pudo detectar el Flipper. Conéctalo o especifica el puerto manualmente (-p).{C_RESET}")
            sys.exit(1)
    else:
        print(f"[*] Usando puerto manual: {port_to_use}")

    try:
        bridge = FlipperBridge(port_to_use)
    except Exception as e:
        print(f"{C_RED}[!] Error al conectar: {e}{C_RESET}")
        sys.exit(1)

    print(f"[*] Descargando log crudo: {args.file}...")
    try:
        raw_bytes = bridge.file_read(args.file)
        raw_text = raw_bytes.decode('utf-8')
    except Exception:
        print(f"{C_RED}[!] No se pudo leer el archivo. ¿Hiciste el ataque en el Flipper primero?{C_RESET}")
        sys.exit(1)

    if not raw_text.strip().startswith("Sec "):
        print(f"{C_RED}[!] El archivo no parece ser de Momentum.{C_RESET}")
        sys.exit(1)

    formatted_text = format_momentum_to_v3(raw_text)

    print("\n[*] Iniciando ataque de fuerza bruta:\n")
    fn = FlipperNested()
    fn.filename = "auto_mem_file.log"
    
    if not fn.parse_file(formatted_text):
        print(f"{C_RED}[!] Falló el parseo interno.{C_RESET}")
        sys.exit(1)
        
    # --- SECUESTRO INTELIGENTE DE LA TERMINAL ---
    original_stdout = sys.stdout
    sys.stdout = PrettyPrinter(sys.stdout)
    
    # Ejecutamos el crack de la librería
    fn.recover_keys()
    
    # --- DEVOLVEMOS LA TERMINAL A LA NORMALIDAD ---
    sys.stdout = original_stdout
    print("")

    nuevas_llaves = set()
    for key_type in fn.found_keys:
        for sec in fn.found_keys[key_type]:
            for key in fn.found_keys[key_type][sec]:
                nuevas_llaves.add(key.upper())

    if not nuevas_llaves:
        print(f"{C_YELLOW}[-] No se descubrieron llaves nuevas.{C_RESET}")
        sys.exit(0)

    print(f"[*] Actualizando el diccionario con {C_GREEN}{len(nuevas_llaves)}{C_RESET} llave(s)...")
    dict_path = "/ext/nfc/assets/mf_classic_dict_user.nfc"
    
    try:
        dict_bytes = bridge.file_read(dict_path)
        dict_text = dict_bytes.decode('utf-8')
    except:
        dict_text = ""

    llaves_agregadas = 0
    for key in nuevas_llaves:
        if key not in dict_text:
            dict_text += f"\n{key}"
            llaves_agregadas += 1

    if llaves_agregadas > 0:
        clean_dict = "\n".join([line for line in dict_text.splitlines() if line.strip()])
        bridge.file_write(dict_path, clean_dict.encode('utf-8'))
        print(f"[+] {C_GREEN}¡Completado!{C_RESET} Se inyectaron {llaves_agregadas} llaves a tu Flipper.")
    else:
        print(f"{C_YELLOW}[*] Las llaves encontradas ya estaban registradas en el Flipper.{C_RESET}")

if __name__ == "__main__":
    main()
