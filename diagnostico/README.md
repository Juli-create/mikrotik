# EVG-DIAG — Diagnóstico de MikroTik desde el navegador

Programa local que se conecta a la API de RouterOS, ejecuta una batería de
**comandos de solo lectura** y muestra los hallazgos en una página web con su
severidad y los comandos sugeridos para corregir cada uno.

**No modifica nada en el router.** Los comandos de corrección se muestran para
que los apliques tú, con criterio y en safe-mode.

## Por qué hace falta un programa y no basta un HTML

Un navegador no puede abrir conexiones TCP crudas: no habla ni SSH ni la API de
RouterOS. Por eso el paquete son dos piezas:

- `evgdiag.py` — servidor local en Python que sí habla con el router.
- `ui.html` — la página donde metes los datos y ves el resultado.

Todo corre en tu máquina. El servidor escucha **solo en 127.0.0.1**, la
contraseña vive en memoria durante la consulta y no se escribe en disco ni sale
a internet.

## Requisitos

- **Python 3.8 o superior.** Sin `pip install`: solo librería estándar.
  - Windows: `winget install Python.Python.3.12` o desde [python.org](https://www.python.org/downloads/).
  - Linux/macOS: normalmente ya está (`python3 --version`).
- El servicio **api** habilitado en el router:
  ```
  /ip service enable api           # puerto 8728, sin cifrar
  /ip service enable api-ssl       # puerto 8729, cifrado (recomendado)
  ```
- Un usuario de RouterOS que pueda leer la configuración. Con permisos de solo
  lectura basta y es lo más prudente:
  ```
  /user group add name=auditor policy=read,api,winbox,test
  /user add name=auditor group=auditor password=UNA_CLAVE_LARGA
  ```

## Uso

```
cd diagnostico
python3 evgdiag.py
```

Imprime un enlace con un token y abre el navegador. Rellena IP, puerto, usuario
y contraseña, y pulsa **Ejecutar diagnóstico**.

En Windows, si `python3` no funciona, usa `py evgdiag.py`.

### Sin navegador (terminal, automatizable)

```
python3 evgdiag.py --cli --host 192.168.88.1 --usuario auditor
python3 evgdiag.py --cli --host 192.168.88.1 --usuario auditor --tls --json informe.json
```

La contraseña se pide por teclado si no se pasa con `--password`. El código de
salida es `2` si hay hallazgos críticos o altos, `0` si no — útil para
monitoreo periódico.

## Qué revisa

| Área | Chequeos |
|---|---|
| Servicios | telnet/ftp/www/api en claro, servicios sin restricción de origen |
| Usuarios | `admin` por defecto, usuarios sin IP de origen, exceso de grupo `full` |
| SSH | `strong-crypto`, login por contraseña |
| Firewall | cierre de `input`, reglas inalcanzables tras el drop, puertos de administración abiertos a cualquier origen, cierre de `forward`, reglas deshabilitadas |
| NAT | redirecciones activas, **dst-nat hacia 127.0.0.1** (indicio de compromiso) |
| DNS | resolver abierto (amplificación) y si el 53 está tapado en WAN |
| Descubrimiento | MNDP/CDP/LLDP amplio, MAC-Telnet y MAC-WinBox |
| Servicios de riesgo | SOCKS, proxy web, UPnP, SMB, RoMON, bandwidth-test sin autenticación |
| SNMP | habilitado, comunidades por defecto (`public`/`private`) |
| Persistencia | scripts y tareas con `fetch`, URLs, base64, `:execute`, creación de usuarios |
| Sistema | versión, firmware RouterBOOT, CPU y memoria, NTP, IP Cloud, direcciones públicas |
| EVG-FW2026 | presencia de las listas `CPE-*`/`EVG-*`, equipos en `CPE-INFECTADO`, tarea de `EVG-CALIBRA` |

Los scripts cuyo nombre empieza por `EVG` se omiten del análisis de
persistencia: son los de este repositorio.

## Seguridad del propio programa

- Escucha únicamente en `127.0.0.1`; rechaza peticiones con otro `Host`.
- Cada arranque genera un token aleatorio: sin él la página y la API devuelven
  403. Eso evita que una web abierta en otra pestaña hable con el servidor.
- Sobre `api` (8728) el protocolo va **sin cifrar**. Para un router en IP
  pública marca *api-ssl*. RouterOS trae certificado autofirmado, así que el
  programa no verifica la cadena: protege de escucha pasiva, no de un
  intermediario activo. Lo sólido es entrar por VPN y usar la IP privada.

## Archivos

- `evgdiag.py` — servidor local, interfaz web y modo `--cli`.
- `rosapi.py` — cliente de la API nativa de RouterOS (login moderno y MD5 antiguo).
- `chequeos.py` — la batería de diagnóstico. Añadir un chequeo es añadir un método `chk_*`.
- `ui.html` — la interfaz.
