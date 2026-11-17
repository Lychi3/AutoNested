import sys
import io
import re
import os
import tempfile
import argparse
import serial.tools.list_ports
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

# Importaciones opcionales para evitar crash si no están instaladas
try:
    from FlipperNested.main import FlipperNested
    from FlipperNested.bridge import FlipperBridge
    FLIPPER_LIB_AVAILABLE = True
except ImportError:
    FLIPPER_LIB_AVAILABLE = False
    print("[!] ADVERTENCIA: Librería FlipperNested no encontrada. Instala las dependencias.")

# ==========================================
# CONFIGURACIÓN VISUAL Y COLORES (CLI)
# ==========================================
C_GREEN = '\033[92m'
C_CYAN = '\033[96m'
C_RED = '\033[91m'
C_YELLOW = '\033[93m'
C_RESET = '\033[0m'

class PrettyPrinter:
    """Intercepta y embellece los mensajes de texto de la terminal (Modo Cable)"""
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout
        self.buffer = ""
        self.current_k_type = "?"
        self.current_sec = "?"

    def write(self, text):
        self.buffer += text
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            self.process_line(line)

    def process_line(self, msg):
        msg = msg.strip()
        if not msg:
            return
        if msg.startswith("Recovering key type"):
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
                self.original_stdout.write(f"{C_YELLOW}Intento fallido (Requiere Hardnested / Distancia Variable){C_RESET}\n")
            else:
                llaves_str = msg.split(":", 1)[-1].strip()
                llaves_limpias = llaves_str.replace("[", "").replace("]", "").replace("'", "").replace(" ", "").upper()
                self.original_stdout.write(f"{C_GREEN}¡ÉXITO! {C_RESET}La Llave {self.current_k_type} es: {C_GREEN}{llaves_limpias}{C_RESET}\n")
        elif "Failed to find keys" in msg:
            self.original_stdout.write(f"   {C_RED}✘ Falló la extracción para este sector.{C_RESET}\n")
        elif "Stopping" in msg:
            self.original_stdout.write(f"\n{C_RED}[!] Deteniendo proceso...{C_RESET}\n")

    def flush(self):
        self.original_stdout.flush()

# ==========================================
# FUNCIONES AUXILIARES
# ==========================================
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
    """Convierte el log crudo de Momentum al formato estricto de FlipperNested V3"""
    formatted_lines = [
        "Filetype: Flipper Nested Nonce Manifest File",
        "Version: 3",
        "Note:"
    ]
    for line in raw_text.splitlines():
        line = line.strip()
        if line.startswith("Sec "):
            p = line.split()
            # Validación de formato mínimo antes de parsear
            if len(p) < 18:
                continue
            try:
                new_line = (
                    f"Nested: Key {p[3]} cuid 0x{p[5]} "
                    f"nt0 0x{p[7]} ks0 0x{p[9]} par0 {p[11]} "
                    f"nt1 0x{p[13]} ks1 0x{p[15]} par1 {p[17]} sec {p[1]}"
                )
                formatted_lines.append(new_line)
            except IndexError:
                continue  # Ignorar líneas malformadas
    return "\n".join(formatted_lines)

def run_crack(formatted_text):
    """
    Ejecuta el crack de FlipperNested sobre el texto formateado.
    Usa un archivo temporal para compatibilidad con la librería.
    Retorna lista de dicts con las llaves encontradas.
    """
    if not FLIPPER_LIB_AVAILABLE:
        raise RuntimeError("La librería FlipperNested no está instalada.")

    # Escribir en archivo temporal porque FlipperNested.parse_file()
    # puede necesitar una ruta real en disco, no texto en memoria.
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.log', delete=False, encoding='utf-8'
    ) as tmp:
        tmp.write(formatted_text)
        tmp_path = tmp.name

    try:
        fn = FlipperNested()
        fn.filename = tmp_path

        # Intentar pasar el texto directo primero; si falla, pasar la ruta
        parsed = False
        try:
            parsed = fn.parse_file(formatted_text)
        except TypeError:
            # La librería espera una ruta, no el texto
            parsed = fn.parse_file(tmp_path)

        if not parsed:
            raise ValueError("Error interno al parsear el log formateado. Verifica el formato del archivo .nested.log")

        # FlipperNested imprime las llaves encontradas por stdout (print()).
        # En modo web NO queremos eso: si este proceso corre 24/7 en un
        # servidor (systemd, nohup, docker, etc.) cualquier redirección de
        # stdout a un log dejaría las llaves de otras personas en disco.
        # Las descartamos por completo; el resultado real sale de fn.found_keys.
        original_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            fn.recover_keys()
        finally:
            sys.stdout = original_stdout

        results = []
        for key_type in fn.found_keys:
            for sec in fn.found_keys[key_type]:
                for key in fn.found_keys[key_type][sec]:
                    results.append({
                        "sector": sec,
                        "type": key_type,
                        "key": key.upper()
                    })
        return results

    finally:
        # Siempre limpiar el archivo temporal
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

# ==========================================
# MODO WEB (SERVIDOR API FLASK)
# ==========================================
app = Flask(__name__)
CORS(app)

# HTML incrustado — despliegue de un solo archivo, sin carpeta static
# La URL de la API se inyecta dinámicamente para que apunte al mismo servidor
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoNested Web</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:          #05060a;
            --bg-2:        #090b11;
            --surface:     #0c0f16;
            --surface-2:   #10141d;
            --surface-3:   #141927;
            --border:      #1c2130;
            --border-lit:  #2d3650;
            --border-glow: #3d4a70;
            --text:        #c9d4e3;
            --text-dim:    #8795ab;
            --muted:       #566279;
            --accent:      #00e6b8;
            --accent-dim:  #00a882;
            --accent-glow: rgba(0,230,184,0.35);
            --warn:        #ffb454;
            --error:       #ff5a6e;
            --success:     #00e6b8;
            --blue:        #5aa9ff;
            --flip-orange: #ff7a1a;
            --flip-glow:   rgba(255,122,26,0.35);
            --radius-lg:   18px;
            --radius-md:   12px;
            --radius-sm:   8px;
            --mono: 'JetBrains Mono', monospace;
            --sans: 'Space Grotesk', sans-serif;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        html {
            background: var(--bg);
            scrollbar-color: var(--border-glow) transparent;
        }

        ::selection { background: var(--accent-glow); color: #fff; }

        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background: var(--border-lit);
            border-radius: 8px;
            border: 2px solid transparent;
            background-clip: padding-box;
        }
        ::-webkit-scrollbar-thumb:hover { background: var(--border-glow); background-clip: padding-box; }

        body {
            font-family: var(--sans);
            position: relative;
            isolation: isolate;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 40px 18px 56px;
            overflow-x: hidden;
        }

        /* ---- AMBIENT BACKGROUND ---- */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            z-index: -2;
            background:
                radial-gradient(ellipse 820px 480px at 12% -8%, rgba(255,122,26,0.16), transparent 58%),
                radial-gradient(ellipse 900px 620px at 104% 6%, rgba(0,230,184,0.13), transparent 55%),
                radial-gradient(ellipse 700px 500px at 50% 112%, rgba(90,169,255,0.08), transparent 60%),
                var(--bg);
            animation: ambientDrift 22s ease-in-out infinite alternate;
        }
        body::after {
            content: '';
            position: fixed;
            inset: 0;
            z-index: -1;
            background-image:
                linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px);
            background-size: 42px 42px;
            mask-image: radial-gradient(ellipse 100% 70% at 50% 0%, #000 10%, transparent 85%);
            opacity: 0.5;
        }
        @keyframes ambientDrift {
            from { transform: translate3d(0,0,0) scale(1); }
            to   { transform: translate3d(-1.5%, 1%, 0) scale(1.03); }
        }

        /* ---- HEADER ---- */
        header {
            width: 100%;
            max-width: 600px;
            margin-bottom: 26px;
        }
        .header-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            flex-wrap: wrap;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 13px;
        }
        .brand-mark {
            width: 44px;
            height: 44px;
            flex-shrink: 0;
            border-radius: 13px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(155deg, #171c28, #0a0d13);
            border: 1px solid var(--border-lit);
            box-shadow: 0 0 0 1px rgba(255,255,255,0.03) inset, 0 8px 20px -10px rgba(255,122,26,0.5);
        }
        .brand-mark svg { width: 22px; height: 22px; }
        header h1 {
            font-family: var(--mono);
            font-size: 21px;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.3px;
            line-height: 1.2;
        }
        header h1 span { color: var(--flip-orange); }
        header p {
            font-size: 12px;
            color: var(--muted);
            margin-top: 3px;
            font-family: var(--mono);
            letter-spacing: 0.2px;
        }


        /* ---- CARD ---- */
        .card {
            width: 100%;
            max-width: 600px;
            background: linear-gradient(175deg, var(--surface-2), var(--surface));
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 1px 0 rgba(255,255,255,0.03) inset, 0 16px 40px -24px rgba(0,0,0,0.75);
            transition: border-color .25s, box-shadow .25s;
            position: relative;
        }
        .card-title {
            font-size: 10.5px;
            font-family: var(--mono);
            letter-spacing: 1.8px;
            text-transform: uppercase;
            color: var(--muted);
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .card-title::before {
            content: '';
            width: 6px; height: 6px;
            border-radius: 2px;
            background: var(--border-glow);
            transform: rotate(45deg);
            flex-shrink: 0;
        }

        /* ---- MODE TABS ---- */
        .mode-tabs-card { padding: 5px; border-radius: 16px; }
        .mode-tabs {
            display: flex;
            gap: 4px;
            position: relative;
        }
        .mode-tab {
            flex: 1;
            padding: 13px 14px;
            border: none;
            background: transparent;
            color: var(--muted);
            font-family: var(--mono);
            font-size: 12.5px;
            font-weight: 600;
            letter-spacing: 0.2px;
            border-radius: 11px;
            cursor: pointer;
            transition: color .2s, background .2s;
            position: relative;
            z-index: 1;
        }
        .mode-tab:hover:not(.active) { color: var(--text); background: rgba(255,255,255,0.03); }
        .mode-tab.active {
            background: var(--bg-2);
            color: #fff;
            box-shadow: 0 0 0 1px var(--border-lit) inset, 0 6px 18px -10px rgba(0,0,0,0.6);
        }

        /* ---- STEPS ---- */
        .steps {
            display: flex;
            flex-direction: column;
            gap: 0;
            position: relative;
        }

        .step {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 15px 2px;
            transition: opacity .3s;
            position: relative;
        }
        .step.locked { opacity: 0.38; }

        /* línea conectora entre los pasos */
        .steps::before {
            content: '';
            position: absolute;
            left: 22px;
            top: 40px;
            bottom: 40px;
            width: 2px;
            background: linear-gradient(var(--border-lit), var(--border));
            z-index: 0;
        }

        .step-num {
            width: 44px; height: 44px;
            border-radius: 50%;
            border: 2px solid var(--border-lit);
            background: var(--surface);
            display: flex; align-items: center; justify-content: center;
            font-family: var(--mono);
            font-size: 15px;
            font-weight: 700;
            color: var(--muted);
            flex-shrink: 0;
            transition: .3s cubic-bezier(.4,0,.2,1);
            position: relative;
            z-index: 1;
        }
        .step.done .step-num {
            background: var(--accent);
            border-color: var(--accent);
            color: #000;
            box-shadow: 0 0 0 5px rgba(0,230,184,0.12), 0 0 18px rgba(0,230,184,0.4);
        }
        .step.active .step-num {
            border-color: var(--flip-orange);
            color: #fff;
            background: linear-gradient(155deg, #201a14, var(--surface));
            box-shadow: 0 0 0 5px rgba(255,122,26,0.1);
            animation: ringPulse 2s ease-in-out infinite;
        }
        @keyframes ringPulse {
            0%, 100% { box-shadow: 0 0 0 5px rgba(255,122,26,0.1); }
            50%      { box-shadow: 0 0 0 9px rgba(255,122,26,0.04); }
        }

        .step-body { flex: 1; min-width: 0; }
        .step-label {
            font-weight: 600;
            font-size: 15px;
            color: #fff;
            margin-bottom: 3px;
            letter-spacing: -0.1px;
        }
        .step-sub {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
        }

        .btn-step {
            padding: 12px 20px;
            border-radius: 10px;
            border: none;
            font-family: var(--mono);
            font-size: 12.5px;
            font-weight: 700;
            letter-spacing: 0.2px;
            cursor: pointer;
            transition: transform .15s ease, box-shadow .2s ease, background .2s ease, color .2s ease;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .btn-step.green {
            background: linear-gradient(135deg, #00f5c4, var(--accent-dim));
            color: #002b22;
            box-shadow: 0 6px 20px -6px rgba(0,230,184,0.55);
        }
        .btn-step.green:hover:not(:disabled) { filter: brightness(1.08); transform: translateY(-1px); }
        .btn-step.orange {
            background: linear-gradient(135deg, #ff9a4a, var(--flip-orange));
            color: #2b1200;
            box-shadow: 0 6px 20px -6px rgba(255,122,26,0.55);
        }
        .btn-step.orange:hover:not(:disabled) { filter: brightness(1.08); transform: translateY(-1px); }
        .btn-step.full { width: 100%; }
        .btn-step:disabled {
            background: var(--border);
            color: var(--muted);
            cursor: not-allowed;
            box-shadow: none;
            filter: none;
        }
        .btn-step:active:not(:disabled) { transform: translateY(0) scale(0.98); }

        /* ---- MANUAL MODE ---- */
        .manual-hint {
            font-size: 13px;
            color: var(--text-dim);
            line-height: 1.6;
            margin-bottom: 16px;
        }
        .manual-hint code {
            color: var(--flip-orange);
            font-family: var(--mono);
            font-size: 12px;
            background: rgba(255,122,26,0.08);
            padding: 1px 6px;
            border-radius: 5px;
        }
        .manual-textarea {
            width: 100%;
            height: 140px;
            background: var(--bg-2);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            color: var(--text);
            padding: 13px;
            font-family: var(--mono);
            font-size: 12px;
            line-height: 1.6;
            resize: vertical;
            outline: none;
            transition: border-color .2s, box-shadow .2s;
            margin-bottom: 16px;
        }
        .manual-textarea::placeholder { color: var(--muted); }
        .manual-textarea:focus {
            border-color: var(--border-glow);
            box-shadow: 0 0 0 3px rgba(90,169,255,0.1);
        }

        /* ---- TERMINAL ---- */
        .terminal-frame {
            background: #010203;
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow: hidden;
            box-shadow: 0 0 0 1px rgba(0,230,184,0.04) inset, 0 20px 44px -28px rgba(0,0,0,0.85);
        }
        .terminal-titlebar {
            display: flex;
            align-items: center;
            gap: 7px;
            padding: 11px 14px;
            background: linear-gradient(180deg, #0e1218, #080a0f);
            border-bottom: 1px solid var(--border);
        }
        .terminal-dot { width: 10px; height: 10px; border-radius: 50%; opacity: 0.9; }
        .terminal-dot.red    { background: #ff5f56; }
        .terminal-dot.yellow { background: #ffbd2e; }
        .terminal-dot.green  { background: #27c93f; }
        .terminal-titlebar span {
            margin-left: 6px;
            font-family: var(--mono);
            font-size: 10.5px;
            color: var(--muted);
            letter-spacing: 0.6px;
        }

        #terminal {
            padding: 15px 16px;
            height: 300px;
            overflow-y: auto;
            font-family: var(--mono);
            font-size: 12.5px;
            line-height: 1.8;
            scroll-behavior: smooth;
            background:
                repeating-linear-gradient(rgba(255,255,255,0.012) 0px, rgba(255,255,255,0.012) 1px, transparent 1px, transparent 3px);
        }
        #terminal > div { padding-left: 2px; border-left: 2px solid transparent; }

        .t-normal  { color: #5e7693; }
        .t-info    { color: var(--blue); }
        .t-warn    { color: var(--warn); }
        .t-success { color: var(--accent); font-weight: 600; }
        .t-error   { color: var(--error); }
        .t-key     { color: #fff; font-weight: 700; }

        /* ---- RESULTS ---- */
        #resultsCard {
            display: none;
            border-color: rgba(0,230,184,0.22);
            box-shadow: 0 1px 0 rgba(255,255,255,0.03) inset, 0 0 0 1px rgba(0,230,184,0.06), 0 16px 40px -24px rgba(0,0,0,0.75);
        }
        .results-hint {
            font-size: 12px;
            color: var(--muted);
            margin-bottom: 14px;
            line-height: 1.55;
        }
        .results-hint code {
            color: var(--accent);
            font-family: var(--mono);
            background: rgba(0,230,184,0.08);
            padding: 1px 6px;
            border-radius: 5px;
        }
        .keys-grid {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .key-row {
            display: flex;
            align-items: center;
            gap: 12px;
            background: var(--bg-2);
            border: 1px solid var(--border);
            border-left: 3px solid var(--border-lit);
            border-radius: var(--radius-sm);
            padding: 12px 14px;
            transition: border-color .2s, transform .2s, background .2s;
        }
        .key-row:hover {
            border-color: var(--border-glow);
            background: var(--surface-3);
            transform: translateX(2px);
        }
        .key-row:has(.key-badge.A) { border-left-color: var(--accent); }
        .key-row:has(.key-badge.B) { border-left-color: var(--blue); }
        .key-badge {
            font-family: var(--mono);
            font-size: 10px;
            font-weight: 800;
            padding: 4px 9px;
            border-radius: 6px;
            flex-shrink: 0;
            letter-spacing: 0.3px;
        }
        .key-badge.A { background: rgba(0,230,184,0.15); color: var(--accent); }
        .key-badge.B { background: rgba(90,169,255,0.15); color: var(--blue); }
        .key-sector {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
            min-width: 58px;
        }
        .key-value {
            font-family: var(--mono);
            font-size: 14px;
            font-weight: 700;
            color: #fff;
            letter-spacing: 1.2px;
            flex: 1;
            overflow-x: auto;
            white-space: nowrap;
        }
        .btn-copy {
            background: none;
            border: 1px solid var(--border);
            color: var(--muted);
            padding: 6px 12px;
            border-radius: 7px;
            cursor: pointer;
            font-family: var(--mono);
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.2px;
            transition: .2s;
            flex-shrink: 0;
        }
        .btn-copy:hover { border-color: var(--accent); color: var(--accent); background: rgba(0,230,184,0.06); }
        .btn-copy.copied { border-color: var(--accent); color: var(--accent); background: rgba(0,230,184,0.1); }

        /* ---- FOOTER ---- */
        footer {
            width: 100%;
            max-width: 600px;
            text-align: center;
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
            margin-top: 14px;
            padding: 0 4px;
            line-height: 1.7;
        }
        footer a { color: var(--text-dim); text-decoration: none; border-bottom: 1px solid transparent; transition: .2s; }
        footer a:hover { color: var(--accent); border-bottom-color: currentColor; }
        footer .dim { color: var(--muted); }

        /* ---- ANIMATIONS ---- */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .fade-in { animation: fadeIn .35s cubic-bezier(.2,.8,.2,1) forwards; }

        /* ---- SERIAL WARNING ---- */
        .serial-warning {
            background: rgba(255,180,84,0.08);
            border: 1px solid rgba(255,180,84,0.25);
            border-radius: var(--radius-sm);
            padding: 13px 14px;
            font-family: var(--mono);
            font-size: 11px;
            line-height: 1.6;
            color: var(--warn);
            margin-top: 16px;
            display: none;
        }
        .serial-warning.show { display: block; animation: fadeIn .3s ease forwards; }

        /* ---- RESPONSIVE ---- */
        @media (max-width: 420px) {
            body { padding: 28px 14px 40px; }
            .card { padding: 18px; border-radius: 14px; }
            header h1 { font-size: 18px; }
            .step-label { font-size: 14px; }
            .btn-step { padding: 10px 14px; font-size: 11.5px; }
            .key-value { font-size: 12.5px; }
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; }
        }
    </style>
</head>
<body>

<header>
    <div class="header-row">
        <div class="brand">
            <div class="brand-mark">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M8.5 11.5a4 4 0 1 1 3.9-5H21l2 2-1.5 1.5L20 8.5 18.5 10 16 7.5h-3.6a4 4 0 0 1-3.9 4z" fill="#ff7a1a"/>
                    <circle cx="8.5" cy="7.5" r="1.4" fill="#0c0f16"/>
                </svg>
            </div>
            <div>
                <h1>Auto<span>Nested</span></h1>
                <p>Flipper Zero · MIFARE Classic Key Recovery</p>
            </div>
        </div>
    </div>
</header>

<!-- MODE TABS -->
<div class="card mode-tabs-card">
    <div class="mode-tabs">
        <button class="mode-tab active" id="tabCable" data-mode="cable">Cable (USB)</button>
        <button class="mode-tab" id="tabManual" data-mode="manual">Manual</button>
    </div>
</div>

<!-- CABLE FLOW -->
<div class="card" id="cableFlow">
    <div class="card-title">// Flujo de trabajo</div>
    <div class="steps">

        <!-- STEP 1: USB SERIAL -->
        <div class="step active" id="step1">
            <div class="step-num" id="step1Num">1</div>
            <div class="step-body">
                <div class="step-label">Conectar Flipper por cable</div>
                <div class="step-sub" id="step1Sub">Web Serial · Chrome / Edge · Solo PC</div>
            </div>
            <button class="btn-step orange" id="btnConnect">Conectar</button>
        </div>

        <!-- STEP 2: RECOVER (crack + inject) -->
        <div class="step locked" id="step2">
            <div class="step-num" id="step2Num">2</div>
            <div class="step-body">
                <div class="step-label">Recuperar llaves</div>
                <div class="step-sub">Lee, rompe e inyecta las llaves automáticamente</div>
            </div>
            <button class="btn-step green" id="btnRecover" disabled>Recuperar</button>
        </div>

    </div>

    <div class="serial-warning" id="serialWarning">
        ⚠ Tu navegador no soporta Web Serial. Usa <strong>Chrome o Edge en PC</strong>. En Android el modo
        cable automático no funciona (ni con cable/adaptador OTG) — usá el modo <strong>Manual</strong> de arriba.
    </div>
</div>

<!-- MANUAL FLOW -->
<div class="card" id="manualFlow" style="display:none">
    <div class="card-title">// Modo manual (sin cable)</div>
    <p class="manual-hint">
        Abre el explorador de archivos de la app oficial de Flipper en tu celular, copiá el contenido de
        <code>/ext/nfc/.nested.log</code> y pegalo acá. Vas a tener que agregar las llaves encontradas
        al diccionario a mano.
    </p>
    <textarea id="manualLogArea" class="manual-textarea" placeholder="Sec 0 key A cuid aa6ce6c9 nt0 62e5bdcf ..."></textarea>
    <button class="btn-step green full" id="btnManualRecover">Recuperar llaves</button>
</div>

<!-- TERMINAL -->
<div class="card">
    <div class="card-title">// Terminal</div>
    <div class="terminal-frame">
        <div class="terminal-titlebar">
            <div class="terminal-dot red"></div>
            <div class="terminal-dot yellow"></div>
            <div class="terminal-dot green"></div>
            <span>autonested — bash</span>
        </div>
        <div id="terminal">
            <div class="t-info">[AutoNested Web — listo]</div>
            <div class="t-normal">[1] Haz el ataque Nested en el Flipper primero (Momentum)</div>
            <div class="t-normal">[2] Elegí un modo arriba y seguí los pasos</div>
        </div>
    </div>
</div>

<!-- RESULTS -->
<div class="card" id="resultsCard">
    <div class="card-title">// Llaves recuperadas</div>
    <div class="results-hint" id="resultsHint" style="display:none">
        Copiá estas llaves y agregalas a mano al flipper.
    </div>
    <div class="keys-grid" id="keysGrid"></div>
</div>

<footer>
    AutoNested Web &nbsp;·&nbsp; powered by <a href="https://github.com/AloneLiberty/FlipperNested" target="_blank">FlipperNested</a>
    <br><span class="dim">Uso exclusivo en pruebas de seguridad sobre tarjetas propias</span>
</footer>

<script>
// ================================================================
//  ESTADO GLOBAL
// ================================================================
const API_BASE = window.location.origin;

const state = {
    mode:            'cable',    // 'cable' | 'manual'
    serverOk:        false,
    serialConnected: false,
    serialLink:      null,       // instancia de FlipperSerialLink
    foundKeys:       [],        // [{sector, type, key}]
};

// Vendor/Product ID reales del Flipper Zero (placa STM32 WB55), usados también
// por FlipperNested/bridge.py para autodetectar el puerto por USB.
const FLIPPER_USB_FILTER = { usbVendorId: 0x0483, usbProductId: 0x5740 };

// ================================================================
//  REFERENCIAS DOM
// ================================================================
const $ = id => document.getElementById(id);
const btnConnect       = $('btnConnect');
const btnRecover       = $('btnRecover');
const btnManualRecover = $('btnManualRecover');
const terminal         = $('terminal');

// ================================================================
//  TERMINAL
// ================================================================
function log(msg, type = 'normal') {
    const div = document.createElement('div');
    div.className = `t-${type} fade-in`;
    div.textContent = `> ${msg}`;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}

function logKey(sector, type, key) {
    const div = document.createElement('div');
    div.className = 'fade-in';
    div.innerHTML = `<span style="color:#4a6080">> Sector </span>`
        + `<span style="color:#f0a040">${String(sector).padStart(2,'0')}</span> `
        + `<span style="color:#4a6080">Key </span>`
        + `<span style="color:#4a9eff">${type}</span>  `
        + `<span class="t-key">${key}</span>`;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}

// ================================================================
//  SELECTOR DE MODO (Cable / Manual)
// ================================================================
$('tabCable').addEventListener('click', () => setMode('cable'));
$('tabManual').addEventListener('click', () => setMode('manual'));

function setMode(mode) {
    state.mode = mode;
    $('tabCable').classList.toggle('active', mode === 'cable');
    $('tabManual').classList.toggle('active', mode === 'manual');
    $('cableFlow').style.display  = mode === 'cable'  ? '' : 'none';
    $('manualFlow').style.display = mode === 'manual' ? '' : 'none';
    $('resultsCard').style.display = 'none';
    $('resultsHint').style.display = mode === 'manual' ? 'block' : 'none';
}

// ================================================================
//  ESTADO DE PASOS UI
// ================================================================
function setStepDone(n) {
    const step = $(`step${n}`);
    step.classList.remove('locked', 'active');
    step.classList.add('done');
    $(`step${n}Num`).textContent = '✓';
}
function unlockStep(n) {
    const step = $(`step${n}`);
    step.classList.remove('locked');
    step.classList.add('active');
}

// ================================================================
//  PASO 1: CONEXIÓN POR CABLE (Web Serial)
// ================================================================
btnConnect.addEventListener('click', async () => {
    if (!('serial' in navigator)) {
        $('serialWarning').classList.add('show');
        log('Web Serial no disponible en este navegador.', 'error');
        log('Usa Chrome o Edge en PC. En Android probá el modo "Manual" de arriba.', 'warn');
        return;
    }

    log('Elegí el puerto del Flipper en el diálogo del navegador...', 'warn');
    btnConnect.disabled = true;
    btnConnect.textContent = 'Buscando...';

    try {
        const port = await navigator.serial.requestPort({ filters: [FLIPPER_USB_FILTER] });
        port.addEventListener('disconnect', onSerialDisconnect);

        log('Puerto seleccionado · Abriendo conexión serial...', 'warn');
        state.serialLink = new FlipperSerialLink(port);
        await state.serialLink.connect();
        log('CLI del Flipper detectada y lista.', 'success');

        state.serialConnected = true;
        btnConnect.textContent = '✓ Conectado';
        btnConnect.style.background = '#1a3a5c';
        btnConnect.style.color = 'var(--blue)';
        btnConnect.disabled = false;

        $('step1Sub').textContent = 'Cable USB · CLI conectada';
        setStepDone(1);
        unlockStep(2);
        btnRecover.disabled = false;

        log('¡Flipper conectado! Ya podés recuperar las llaves.', 'success');

    } catch (err) {
        log(`Fallo la conexión serial: ${err.message}`, 'error');
        if (err.name === 'NotFoundError') {
            log('No seleccionaste ningún puerto, o el Flipper no está conectado por USB.', 'warn');
        }
        btnConnect.disabled = false;
        btnConnect.textContent = 'Reintentar';
        btnConnect.style.background = 'rgba(255,80,96,0.2)';
        btnConnect.style.color = 'var(--error)';
    }
});

function onSerialDisconnect() {
    log('Se perdió la conexión USB con el Flipper.', 'error');
    state.serialConnected = false;
    state.serialLink      = null;
    btnConnect.textContent = 'Reconectar';
    btnConnect.disabled = false;
    btnConnect.style.background = '';
    btnConnect.style.color = '';
    btnRecover.disabled = true;
    $('step1').classList.remove('done');
    $('step1').classList.add('active');
    $('step1Num').textContent = '1';
}

// ================================================================
//  ENLACE SERIAL REAL: automatiza la CLI de texto del Flipper por USB.
//  Es la MISMA CLI que FlipperNested/bridge.py usa como paso previo a
//  "start_rpc_session" (ver bridge.py: lee hasta el prompt ">: ").
//  Como .nested.log y el diccionario son archivos de texto plano, no
//  hace falta pasar a modo RPC en protobuf: alcanza con automatizar
//  "storage read"/"storage write" tal cual se escriben a mano en un
//  terminal serial, y esperar a que el prompt reaparezca para saber
//  cuándo terminó cada comando.
// ================================================================
const FLIPPER_PROMPT = '>: ';

class FlipperSerialLink {
    constructor(port) {
        this.port = port;
        this.reader = null;
        this.writer = null;
        this.buffer = '';
        this.readLoopPromise = null;
        this.closed = false;
    }

    async connect() {
        await this.port.open({ baudRate: 115200 });
        this.reader = this.port.readable.getReader();
        this.writer = this.port.writable.getWriter();
        this.readLoopPromise = this._readLoop();

        // Ctrl+C + Enter: corta cualquier línea a medio escribir y fuerza
        // a que la CLI vuelva a imprimir su prompt, sin importar en qué
        // estado haya quedado una sesión anterior.
        await this._write('\x03\r');
        await this._waitForPrompt(5000);
    }

    async _readLoop() {
        try {
            for (;;) {
                const { value, done } = await this.reader.read();
                if (done) break;
                this.buffer += new TextDecoder().decode(value);
            }
        } catch (err) {
            if (!this.closed) console.error('Error leyendo del puerto serial', err);
        }
    }

    async _write(text) {
        await this.writer.write(new TextEncoder().encode(text));
    }

    async _waitForPrompt(timeoutMs = 10000) {
        const start = Date.now();
        while (!this.buffer.includes(FLIPPER_PROMPT)) {
            if (Date.now() - start > timeoutMs) {
                throw new Error('Timeout esperando el prompt de la CLI del Flipper');
            }
            await new Promise(r => setTimeout(r, 30));
        }
        const captured = this.buffer;
        this.buffer = '';
        return captured;
    }

    async readFile(path) {
        this.buffer = '';
        await this._write(`storage read ${path}\r`);
        const raw = await this._waitForPrompt();
        // storage_cli.c imprime "Size: <N>" antes del contenido (ver storage_cli_read()),
        // además del eco del comando y la línea del prompt: los tres se descartan.
        const content = raw.split(/\r?\n/)
            .filter(line =>
                !line.includes(`storage read ${path}`) &&
                !line.includes(FLIPPER_PROMPT.trim()) &&
                !/^Size:\s*\d+$/.test(line.trim())
            )
            .join('\n')
            .trim();
        if (/storage error|cannot|failed/i.test(content)) {
            throw new Error(`El Flipper no pudo leer ${path}: ${content}`);
        }
        return content;
    }

    async writeFile(path, content) {
        // Borramos el archivo previo para no dejar restos si el nuevo es más corto.
        this.buffer = '';
        await this._write(`storage remove ${path}\r`);
        await this._waitForPrompt().catch(() => {}); // puede no existir todavía, no importa

        this.buffer = '';
        await this._write(`storage write ${path}\r`);
        await new Promise(r => setTimeout(r, 200)); // la CLI pasa a modo "recibir bytes crudos"

        const CHUNK = 512; // igual al tamaño de chunk que usa bridge.py por RPC
        for (let i = 0; i < content.length; i += CHUNK) {
            await this._write(content.slice(i, i + CHUNK));
            await new Promise(r => setTimeout(r, 30));
        }
        if (!content.endsWith('\n')) await this._write('\n');
        await new Promise(r => setTimeout(r, 150));
        await this._write('\x03'); // Ctrl+C: cierra el archivo y vuelve al prompt
        await this._waitForPrompt();
    }

    async disconnect() {
        this.closed = true;
        try { await this.reader?.cancel(); } catch {}
        try { this.writer?.releaseLock(); } catch {}
        try { await this.readLoopPromise; } catch {}
        try { await this.port.close(); } catch {}
    }
}

// ================================================================
//  ENVÍO AL SERVIDOR PARA CRACKEAR (compartido por ambos modos)
// ================================================================
async function runCrack(rawLog) {
    const response = await fetch(API_BASE + '/crack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_log: rawLog })
    });
    const data = await response.json();
    if (!response.ok || data.error) {
        throw new Error(data.error || `HTTP ${response.status}`);
    }
    return data;
}

function showResults(keys) {
    log(`¡ÉXITO! Se recuperaron ${keys.length} llaves:`, 'success');
    state.foundKeys = keys;
    $('keysGrid').innerHTML = '';
    keys.forEach(k => {
        logKey(k.sector, k.type, k.key);
        addKeyToResults(k);
    });
    $('resultsCard').style.display = 'block';
}

// ================================================================
//  PASO 2 (MODO CABLE): RECUPERAR LLAVES — leer + crackear + inyectar
// ================================================================
btnRecover.addEventListener('click', async () => {
    if (!state.serialConnected) return;

    btnRecover.disabled = true;
    btnRecover.textContent = 'Trabajando...';
    state.foundKeys = [];
    $('resultsCard').style.display = 'none';

    try {
        if (!state.serverOk) {
            throw new Error(`No se pudo contactar el servidor Python en ${API_BASE}`);
        }

        log('Leyendo /ext/nfc/.nested.log por USB...', 'warn');
        let rawLog;
        try {
            rawLog = await state.serialLink.readFile('/ext/nfc/.nested.log');
            if (!rawLog || rawLog.trim().length === 0) {
                throw new Error('Archivo vacío o no encontrado');
            }
            log(`Archivo leído (${rawLog.length} bytes). Enviando al servidor...`, 'info');
        } catch (serialErr) {
            log(`Lectura por USB no disponible: ${serialErr.message}`, 'error');
            log('Probá el modo "Manual" (arriba) para pegar el log a mano.', 'warn');
            return;
        }

        const data = await runCrack(rawLog);

        if (data.keys_found === 0) {
            log('El servidor procesó el log pero no encontró llaves.', 'warn');
            log('Puede que se necesite el modo Hardnested o más nonces.', 'warn');
            return;
        }

        showResults(data.keys);
        await injectKeys();
        setStepDone(2);

    } catch (err) {
        if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
            log(`Error de red: no se pudo contactar ${API_BASE}`, 'error');
            log('¿El servidor Python sigue corriendo?', 'warn');
        } else {
            log(`Error: ${err.message}`, 'error');
        }
    } finally {
        btnRecover.disabled = false;
        btnRecover.textContent = 'Recuperar';
    }
});

// ================================================================
//  INYECTAR LLAVES AL FLIPPER (parte final del modo Cable)
// ================================================================
async function injectKeys() {
    if (state.foundKeys.length === 0) return;

    const dictPath = '/ext/nfc/assets/mf_classic_dict_user.nfc';
    log(`Leyendo diccionario existente: ${dictPath}...`, 'warn');

    let existingDict = '';
    try {
        existingDict = await state.serialLink.readFile(dictPath);
        log(`Diccionario leído (${existingDict.split('\n').filter(l=>l.trim()).length} entradas).`, 'info');
    } catch {
        log('Diccionario no encontrado, se creará uno nuevo.', 'warn');
        existingDict = '';
    }

    // Filtrar llaves ya existentes
    const newKeys = state.foundKeys.filter(k => !existingDict.includes(k.key));

    if (newKeys.length === 0) {
        log('Todas las llaves encontradas ya estaban en el diccionario.', 'warn');
        return;
    }

    const appendText = newKeys.map(k => k.key).join('\n');
    const updatedDict = [existingDict, appendText]
        .join('\n')
        .split('\n')
        .filter(l => l.trim())
        .join('\n');

    log(`Escribiendo ${newKeys.length} llaves nuevas al diccionario...`, 'warn');
    try {
        await state.serialLink.writeFile(dictPath, updatedDict);
        log(`¡Completado! ${newKeys.length} llaves inyectadas al Flipper.`, 'success');
    } catch (err) {
        log(`Error al escribir en el Flipper: ${err.message}`, 'error');
        log('Fallback: Copia las llaves del cuadro de resultados y agrégalas manualmente.', 'warn');
    }
}

// ================================================================
//  MODO MANUAL: pegar el log a mano, sin cable ni inyección automática
// ================================================================
btnManualRecover.addEventListener('click', async () => {
    const rawLog = $('manualLogArea').value.trim();
    if (!rawLog) {
        log('Pegá el contenido del log primero.', 'warn');
        return;
    }

    btnManualRecover.disabled = true;
    btnManualRecover.textContent = 'Trabajando...';
    state.foundKeys = [];
    $('resultsCard').style.display = 'none';

    try {
        if (!state.serverOk) {
            throw new Error(`No se pudo contactar el servidor Python en ${API_BASE}`);
        }

        log('Enviando log pegado manualmente al servidor...', 'info');
        const data = await runCrack(rawLog);

        if (data.keys_found === 0) {
            log('El servidor procesó el log pero no encontró llaves.', 'warn');
            log('Puede que se necesite el modo Hardnested o más nonces.', 'warn');
            return;
        }

        showResults(data.keys);
        log('Copiá estas llaves y agregalas a mano en el flipper.', 'info');

    } catch (err) {
        if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
            log(`Error de red: no se pudo contactar ${API_BASE}`, 'error');
        } else {
            log(`Error: ${err.message}`, 'error');
        }
    } finally {
        btnManualRecover.disabled = false;
        btnManualRecover.textContent = 'Recuperar llaves';
    }
});

// ================================================================
//  RESULTADOS: AGREGAR FILA DE LLAVE
// ================================================================
function addKeyToResults(k) {
    const grid = $('keysGrid');
    const row = document.createElement('div');
    row.className = 'key-row fade-in';
    row.innerHTML = `
        <span class="key-badge ${k.type}">${k.type}</span>
        <span class="key-sector">Sec ${String(k.sector).padStart(2,'0')}</span>
        <span class="key-value">${k.key}</span>
        <button class="btn-copy" data-key="${k.key}">Copiar</button>
    `;
    row.querySelector('.btn-copy').addEventListener('click', function() {
        navigator.clipboard.writeText(this.dataset.key).then(() => {
            this.textContent = '✓ Copiado';
            this.classList.add('copied');
            setTimeout(() => {
                this.textContent = 'Copiar';
                this.classList.remove('copied');
            }, 1800);
        });
    });
    grid.appendChild(row);
}

// ================================================================
//  AUTO-VERIFICAR SERVIDOR AL CARGAR (silencioso)
// ================================================================
window.addEventListener('load', () => {
    fetch(API_BASE + '/health', { signal: AbortSignal.timeout(3000) })
        .then(r => r.json())
        .then(d => {
            state.serverOk = d.status === 'ok';
            if (!state.serverOk) {
                log('El servidor Python no respondió correctamente.', 'warn');
            } else if (!d.lib_available) {
                log('Servidor en línea, pero FlipperNested no está instalado.', 'warn');
            }
        })
        .catch(() => {
            log(`No se pudo contactar el servidor en ${API_BASE}.`, 'warn');
            log('¿Está corriendo "python main.py -w"?', 'warn');
        });
});
</script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def serve_web():
    """Sirve la interfaz web (la página resuelve la URL del servidor sola, vía window.location.origin)"""
    return Response(_HTML_TEMPLATE, mimetype='text/html')

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de verificación de estado para la app web"""
    return jsonify({
        "status": "ok",
        "lib_available": FLIPPER_LIB_AVAILABLE
    })

@app.route('/crack', methods=['POST'])
def web_crack():
    """Endpoint que recibe el log del Flipper y devuelve las llaves"""
    data = request.get_json(silent=True)

    if not data or 'raw_log' not in data:
        return jsonify({
            "error": "Payload inválido. Se espera JSON con campo 'raw_log'."
        }), 400

    raw_text = data['raw_log'].strip()
    if not raw_text:
        return jsonify({"error": "El campo 'raw_log' está vacío."}), 400

    # Aceptar tanto el formato crudo de Momentum ("Sec X key ...") 
    # como el formato V3 ya formateado
    if raw_text.startswith("Filetype: Flipper Nested"):
        formatted_text = raw_text
    elif raw_text.startswith("Sec "):
        formatted_text = format_momentum_to_v3(raw_text)
    else:
        return jsonify({
            "error": "Formato no reconocido. El log debe empezar con 'Sec ' (Momentum) o con 'Filetype: Flipper Nested' (V3)."
        }), 400

    try:
        results = run_crack(formatted_text)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        return jsonify({"error": f"Error inesperado durante el crack: {str(e)}"}), 500

    return jsonify({
        "success": True,
        "keys_found": len(results),
        "keys": results
    })

def start_web_server(host, port):
    display_host = "127.0.0.1" if host == "0.0.0.0" else host
    print(f"[*] Iniciando AutoNested Web Server...")
    print(f"[*] Librería FlipperNested: {'✓ disponible' if FLIPPER_LIB_AVAILABLE else '✗ NO encontrada'}")
    print(f"")
    print(f"[*] Interfaz web:  http://{display_host}:{port}/")
    print(f"[*] API crack:     POST http://{display_host}:{port}/crack")
    print(f"[*] Health check:  GET  http://{display_host}:{port}/health")
    print(f"")
    if host == "0.0.0.0":
        print(f"[*] Accesible desde la red local — abre la URL de arriba en cualquier dispositivo.")
    print(f"")
    print(f"[!] Modo Cable (USB/Web Serial) solo funciona en PC con Chrome o Edge.")
    print(f"    En Android/celular no está soportado: usá el modo 'Manual' de la interfaz web,")
    print(f"    pegando a mano el contenido de /ext/nfc/.nested.log.")
    print("[*] Listo.\n")
    app.run(host=host, port=port, debug=False)

# ==========================================
# FUNCIÓN PRINCIPAL (ORQUESTADOR)
# ==========================================
def main():
    parser = argparse.ArgumentParser(
        description="AutoNested Flipper Zero Cracker — Modo Cable (USB) y Modo Web (API)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s                              Modo cable, autodetecta el puerto del Flipper\n"
            "  %(prog)s -p /dev/ttyACM0               Modo cable, puerto manual\n"
            "  %(prog)s -f /ext/nfc/otro.log           Modo cable, archivo de log distinto\n"
            "  %(prog)s -w                            Modo web en 0.0.0.0:5000\n"
            "  %(prog)s -w --listen-port 8080          Modo web en otro puerto\n"
            "  %(prog)s -w --host 127.0.0.1            Modo web solo accesible en local\n"
        )
    )

    # Modo Cable (CLI)
    parser.add_argument("-p", "--port",
        help="Puerto COM/tty. Se autodetectará si se omite.")
    parser.add_argument("-f", "--file",
        default="/ext/nfc/.nested.log",
        help="Ruta del archivo log en el Flipper (default: /ext/nfc/.nested.log)")

    # Modo Web (API)
    parser.add_argument("-w", "--web",
        action="store_true",
        help="Activar modo servidor API (Web/Móvil/Termux)")
    parser.add_argument("--host",
        default="0.0.0.0",
        help="Host del servidor (default: 0.0.0.0 para acceso por LAN)")
    parser.add_argument("--listen-port",
        type=int, default=5000,
        help="Puerto del servidor API (default: 5000)")

    args = parser.parse_args()

    # ---------------------------------------------------------
    # RUTA 1: MODO SERVIDOR WEB (API)
    # ---------------------------------------------------------
    if args.web:
        start_web_server(args.host, args.listen_port)
        sys.exit(0)

    # ---------------------------------------------------------
    # RUTA 2: MODO CABLE USB (CLI)
    # ---------------------------------------------------------
    if not FLIPPER_LIB_AVAILABLE:
        print(f"{C_RED}[!] La librería FlipperNested no está disponible. Instala las dependencias.{C_RESET}")
        sys.exit(1)

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
        print(f"{C_RED}[!] Error al conectar con el Flipper: {e}{C_RESET}")
        sys.exit(1)

    print(f"[*] Descargando log crudo: {args.file}...")
    try:
        raw_bytes = bridge.file_read(args.file)
        raw_text = raw_bytes.decode('utf-8')
    except Exception as e:
        print(f"{C_RED}[!] No se pudo leer el archivo '{args.file}': {e}")
        print(f"[!] ¿Hiciste el ataque Nested en el Flipper primero?{C_RESET}")
        sys.exit(1)

    if not raw_text.strip().startswith("Sec "):
        print(f"{C_RED}[!] El archivo no parece tener el formato crudo de Momentum.{C_RESET}")
        print(f"[!] Primera línea: {raw_text.splitlines()[0][:80] if raw_text else '(vacío)'}")
        sys.exit(1)

    formatted_text = format_momentum_to_v3(raw_text)

    print("\n[*] Iniciando ataque de criptoanálisis:\n")

    # Secuestro de stdout para mensajes bonitos
    original_stdout = sys.stdout
    sys.stdout = PrettyPrinter(sys.stdout)

    try:
        results = run_crack(formatted_text)
    except Exception as e:
        sys.stdout = original_stdout
        print(f"\n{C_RED}[!] Error durante el crack: {e}{C_RESET}")
        sys.exit(1)
    finally:
        sys.stdout = original_stdout

    print("")

    if not results:
        print(f"{C_YELLOW}[-] No se descubrieron llaves nuevas.{C_RESET}")
        sys.exit(0)

    nuevas_llaves = set(k["key"] for k in results)
    print(f"[*] Actualizando el diccionario con {C_GREEN}{len(nuevas_llaves)}{C_RESET} llave(s)...")

    dict_path = "/ext/nfc/assets/mf_classic_dict_user.nfc"
    try:
        dict_bytes = bridge.file_read(dict_path)
        dict_text = dict_bytes.decode('utf-8')
    except Exception:
        dict_text = ""
        print(f"[*] No se encontró diccionario existente, se creará uno nuevo.")

    llaves_agregadas = 0
    for key in nuevas_llaves:
        if key not in dict_text:
            dict_text += f"\n{key}"
            llaves_agregadas += 1

    if llaves_agregadas > 0:
        clean_dict = "\n".join([line for line in dict_text.splitlines() if line.strip()])
        bridge.file_write(dict_path, clean_dict.encode('utf-8'))
        print(f"[+] {C_GREEN}¡Completado!{C_RESET} Se inyectaron {llaves_agregadas} llaves nuevas al diccionario del Flipper.")
    else:
        print(f"{C_YELLOW}[*] Las llaves encontradas ya estaban en tu diccionario. No se realizaron cambios.{C_RESET}")

if __name__ == "__main__":
    main()