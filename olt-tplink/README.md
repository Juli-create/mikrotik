# Diagnostico OLT TP-Link DS-P7001-08 (GPON)

Recolector para el caso **"las ONUs no suben"**. Se conecta a la OLT por SSH o
Telnet, corre una bateria de comandos y deja toda la salida en un `.txt`.

> **Importante:** la DS-P7001-08 es **GPON**. Si las ONUs son EPON no van a
> registrar nunca, sin importar la configuracion.

## Uso

```bash
# Requisito: expect
sudo apt install expect          # Debian/Ubuntu
brew install expect              # macOS

OLT_HOST=192.168.1.100 ./recolectar-diagnostico.sh
```

Se ejecuta **desde un equipo que ya ve la OLT** (tu PC en la LAN, un salto SSH,
un contenedor en la red de gestion). No expongas la gestion de la OLT a internet
para correrlo desde afuera.

### Variables

| Variable          | Default | Para que |
|-------------------|---------|----------|
| `OLT_HOST`        | (pide)  | IP de gestion de la OLT |
| `OLT_USER`        | `admin` | Usuario |
| `OLT_PASS`        | (pide)  | Password. Si no la pones, la pide sin eco |
| `OLT_ENABLE_PASS` | =`OLT_PASS` | Password de `enable`, si es distinta |
| `OLT_PROTO`       | `ssh`   | `ssh` o `telnet` |
| `OLT_PORT`        | 22 / 23 | Puerto |
| `OLT_TIMEOUT`     | `25`    | Segundos de espera por comando |

La password **nunca** se pasa por argumento: quedaria visible en `ps` y en el
historial del shell.

### Opciones

```bash
./recolectar-diagnostico.sh --dry-run              # muestra que haria, sin conectarse
./recolectar-diagnostico.sh -c mis-comandos.txt    # tu propia lista de comandos
```

## Como leer el resultado

El diagnostico esta ordenado por capas. Ve en orden:

**1. `show onu unauth` / `autofind` — esto parte el problema en dos:**
- **Sale vacio** -> problema optico o de puerto PON. Ve al punto 2.
- **Salen ONUs pero no autorizan** -> problema de autenticacion. Ve al punto 3.

**2. Optica (`show interface pon`, `transceiver-info`)**
- ¿El puerto esta administrativamente arriba?
- Tx de la OLT: normal ~ +2 a +5 dBm.
- Rx en la ONU: debe estar entre **-8 y -27 dBm**. Fuera de ahi no registra o
  registra inestable.
- Causas tipicas: LED LOS encendido, conector sucio (limpiar con alcohol
  isopropilico), splitter mal balanceado, fibra cortada, fusion mala.

**3. Autenticacion (`show gpon authentication-mode`)**
Causa #1 de "la detecta pero no sube": el modo de la OLT (SN / LOID /
LOID+password) no coincide con el que trae la ONU de fabrica. Si vas por SN,
confirma que sea el de la etiqueta.

**4. Perfiles (`show gpon profile ...`)**
Sin `line profile` y `service profile` (DBA + T-CONT + GEM) creados y asignados,
la ONU puede autorizar y quedar sin servicio, o rebotar. Crea los perfiles
**antes** de autorizar.

**5. Log (`show logging`)**
Aqui salen los `deregister`, los rogue ONU y los flapeos.

Otros que se ven seguido:
- SN ya registrado en otro puerto PON de la misma OLT: la autorizacion falla en
  silencio. Busca duplicados.
- Limite de 128 ONUs por puerto alcanzado.
- **Rogue ONU** (transmite fuera de su timeslot) tumbando el PON entero: si
  *ninguna* ONU sube de golpe en un puerto que antes andaba, desconecta ramas
  del splitter una por una.
- Firmware de ONU con OMCI incompatible (tipico con ONUs de otro fabricante).

## Sobre la sintaxis de los comandos

La sintaxis exacta cambia entre versiones de firmware de la 7001. Si un comando
devuelve `Invalid command` **no es un problema**: el script sigue con el
siguiente y esa respuesta queda en el log, lo que ya nos dice cual es la
sintaxis buena de tu equipo. Ajusta la lista dentro del script o pasa la tuya
con `-c`.

## Antes de compartir el resultado

El `.txt` incluye el `running-config` de la OLT. La password de login se
reemplaza por `***REDACTADO***` automaticamente, pero **revisa el archivo**
antes de pasarlo: el running-config puede llevar comunidades SNMP, usuarios,
claves PPPoE y direccionamiento interno.
