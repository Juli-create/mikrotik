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

Primero mira el **estado** de cada ONU. Eso decide todo lo demas:

| ONLINE | Config  | Active   | Que significa |
|--------|---------|----------|---------------|
| si     | Success | Active   | La ONU trabaja |
| si     | **Failed**  | Inactive | Registro OK, la config no aplico -> **problema de PERFIL** |
| no     | -       | -        | Problema optico o de autenticacion |

`Match: Mismatch` por si solo **no** impide que la ONU trabaje: es un aviso de
que el perfil declara un hardware distinto al que la ONU reporta por OMCI. El
que la deja `Inactive` es `Config: Failed`.

### Caso 1: ONLINE pero Config Failed / Inactive

La fibra y la autenticacion estan bien. No pierdas tiempo midiendo potencias.

La causa casi siempre es que el **service profile declara una capacidad fisica
que la ONU no tiene**: N puertos Ethernet, N POTS, N T-CONT. La config
referencia puertos inexistentes y aborta.

1. Mira la capacidad **real** que reporta la ONU (`show onu capability`, o el
   icono de detalle en la fila del GUI) y comparala con lo que declara el
   perfil asignado.
2. Si otra ONU del mismo PON ya trabaja, **copia su combinacion de perfiles**.
   Es la prueba mas rapida: asignasela a la que falla y refresca.
3. Un `line profile 0` / `service profile 0` suele ser el default vacio del
   equipo y no sirve para dar servicio.
4. Verifica el modelo exacto de la ONU. Un perfil de 4 puertos GE aplicado a
   una ONU bridge de 1 puerto falla siempre. Ejemplos comunes:
   `HG8310M` = 1 GE sin POTS; `HG8245`/`HG8145` = 4 GE + 2 POTS.

Los prefijos del serial dicen el fabricante: `HWTC` = Huawei, `ALCL` =
Alcatel/Nokia, `ZTEG` = ZTE, `TPLG` = TP-Link. Si fallan todas las de un
fabricante y funcionan las de otro, es un perfil que no encaja con ese
hardware, no un problema de red.

### Caso 2: la ONU no llega a ONLINE

Ahora si es capa fisica o autenticacion.

**Optica** (`show interface pon`, `transceiver-info`)
- ¿El puerto esta administrativamente arriba?
- Tx de la OLT: normal ~ +2 a +5 dBm.
- Rx en la ONU: debe estar entre **-8 y -27 dBm**. Fuera de ahi no registra o
  registra inestable.
- Causas tipicas: LED LOS encendido, conector sucio (limpiar con alcohol
  isopropilico), splitter mal balanceado, fibra cortada, fusion mala.

**Autenticacion** (`show gpon authentication-mode`, `show onu unauth`)
- ¿Aparece en `unauth`/`autofind`? Si aparece, la fibra esta bien y el
  problema es el modo de auth (SN / LOID / LOID+password), que debe coincidir
  con el que trae la ONU de fabrica.
- SN ya registrado en otro puerto PON de la misma OLT: la autorizacion falla
  en silencio. Busca duplicados.
- Limite de 128 ONUs por puerto alcanzado.
- **Rogue ONU** (transmite fuera de su timeslot) tumbando el PON entero: si
  *ninguna* ONU sube de golpe en un puerto que antes andaba, desconecta ramas
  del splitter una por una.

**Log** (`show logging`)
Aqui salen los `deregister`, los rogue ONU y los flapeos.

## Trampa: la alarma DDM de rx power baja en un puerto PON

```
Port Gpon1/0/5 SFP Module rx power low alarm
Port Gpon1/0/5 SFP Module rx power recover from the low alarm threshold
```

**Por si sola no indica un problema de fibra.** En un puerto GPON el Rx del SFP
de la OLT es la rafaga upstream de las ONUs. Si ninguna ONU esta transmitiendo,
el Rx es practicamente cero y la OLT dispara la alarma. Cuando una ONU conecta,
sube y "recupera".

Para saber si es causa o consecuencia, **mira el orden de los eventos**:

| Orden | Lectura |
|-------|---------|
| ONU `connected` -> luego `rx power recover` | Normal. La alarma era por ausencia de ONUs. Consecuencia. |
| `rx power recover` -> luego ONU `connected` | La fibra se recupero y por eso subio la ONU. Causa. |

Esta alarma solo significa algo si salta **mientras hay ONUs activas
transmitiendo**.

Lo que si importa son los **dBm reales por ONU**, no los umbrales ni el
agregado del puerto PON. Y un `was connected` en el log implica que antes
estuvo desconectada: filtra el log por esa SN y cuenta los eventos. Si
`connected`/`disconnected` se repite cada pocos minutos, es flapeo real y ahi
si toca revisar conector, fusion y potencia de esa rama.

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
