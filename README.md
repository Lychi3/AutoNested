# AutoNested

Herramienta para automatizar la recuperación de llaves **MIFARE Classic 1k** a partir de los nonces capturados por un **Flipper Zero** (ataque Nested, firmware Momentum), usando la librería [FlipperNested](https://github.com/AloneLiberty/FlipperNestedRecovery).

🌐 Hay una demo del modo web disponible en **[autonested.lychi3.me](https://autonested.lychi3.me)**. El servidor **no almacena** en ningún momento las llaves recuperadas: solo las procesa en memoria y las devuelve a tu navegador.

> ⚠️ **Uso exclusivo para pruebas de seguridad sobre tarjetas propias o con autorización explícita.**

## ¿Qué hace?

1. Lee el log crudo del ataque Nested (`/ext/nfc/.nested.log`) que el Flipper genera.
2. Lo convierte al formato que espera `FlipperNested`.
3. Ejecuta un aatque de fuerza bruta sobre los nonces para recuperar las llaves A/B de cada sector.
4. Inyecta automáticamente las llaves nuevas al diccionario del Flipper.

## Modos disponibles

`autonested.py` es el único script del proyecto, con dos modos de uso:

### 1. Modo Cable (USB)

Conecta con el Flipper por puerto serie (USB), lee el log, rompe las llaves e inyecta el diccionario automáticamente. Funciona por línea de comandos o desde la interfaz web (**Chrome / Edge en PC, vía Web Serial - no soportado en Android**).

### 2. Modo Web (API + interfaz)

Levanta un servidor Flask con una interfaz web embebida (sin archivos estáticos externos), pensada para usarse desde PC o celular:

- **Cable (USB)**: solo en PC, con Chrome/Edge, usando Web Serial.
- **Manual**: pegás a mano el contenido de `.nested.log` (por ejemplo copiado desde la app oficial de Flipper en el celular) y el servidor devuelve las llaves encontradas; después las agregás al diccionario a mano.

Este modo está pensado para dejarlo corriendo (por ejemplo en una Raspberry Pi, un servidor casero o el propio hosting de la demo) y usarlo desde el celular en el modo **Manual** cuando no tienes la PC a mano para conectar el Flipper por cable.

## Requisitos

- Python 3.9+
- Un Flipper Zero (Momentum firmware)
- Dependencias listadas en [`requirements.txt`](requirements.txt)

## Instalación

```bash
git clone https://github.com/Lychi3/AutoNested.git
cd AutoNested
pip install -r requirements.txt
```

## Uso

### Modo Cable (CLI)

```bash
# Autodetecta el puerto del Flipper
python3 autonested.py

# Puerto manual
python3 autonested.py -p /dev/ttyACM0

# Archivo de log distinto al default
python3 autonested.py -f /ext/nfc/otro.log
```

### Modo Web (API + interfaz)

```bash
# Servidor en 0.0.0.0:5000 (accesible desde la LAN)
python3 autonested.py -w

# Puerto distinto
python3 autonested.py -w --listen-port 8080

# Solo accesible en localhost
python3 autonested.py -w --host 127.0.0.1
```

Luego abre `http://<host>:<puerto>/` en el navegador.

### Ayuda completa

```bash
python3 autonested.py -h
```

## Guía paso a paso

📝 En mi blog hay una guía paso a paso completa, desde escanear la tarjeta con el Flipper hasta agregar las llaves recuperadas a mano en el diccionario: **[próximamente](#)**.

## Endpoints de la API web

| Método | Ruta      | Descripción                                               |
|--------|-----------|-------------------------------------------------------------|
| GET    | `/`       | Sirve la interfaz web                                       |
| GET    | `/health` | Estado del servidor y disponibilidad de `FlipperNested`     |
| POST   | `/crack`  | Recibe `{"raw_log": "..."}` y devuelve las llaves encontradas |

## Estructura del proyecto

```
AutoNested/
├── autonested.py     # Script principal: CLI + servidor web
├── requirements.txt  # Dependencias Python
└── README.md
```

## Disclaimer

Este proyecto se publica con fines educativos y de investigación en seguridad. El autor no se hace responsable del uso indebido de esta herramienta. Usala solo sobre tarjetas y sistemas de tu propiedad o con autorización explícita para realizar pruebas de seguridad.
