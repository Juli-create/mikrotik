#!/usr/bin/env bash
#
# Recolector de diagnostico para OLT TP-Link DS-P7001-08 (GPON)
#
# Se ejecuta DESDE UN EQUIPO QUE YA VE LA OLT (tu PC en la LAN, un salto SSH,
# un contenedor en la red de gestion). Se conecta por SSH o Telnet, corre una
# bateria de comandos de diagnostico y guarda toda la salida en un .txt.
#
# Uso:
#   OLT_HOST=192.168.1.100 ./recolectar-diagnostico.sh
#   OLT_HOST=192.168.1.100 OLT_PROTO=telnet OLT_USER=admin ./recolectar-diagnostico.sh
#   ./recolectar-diagnostico.sh -c mis-comandos.txt        # lista de comandos propia
#   ./recolectar-diagnostico.sh --dry-run                  # solo imprime que haria
#
# La contrasena NUNCA se pasa por argumento (quedaria visible en `ps` y en el
# historial del shell). Se toma de la variable OLT_PASS o se pide interactiva.
#
# Requisitos: expect  (Debian/Ubuntu: apt install expect | macOS: brew install expect)

set -uo pipefail

OLT_HOST="${OLT_HOST:-}"
OLT_USER="${OLT_USER:-admin}"
OLT_PASS="${OLT_PASS:-}"
OLT_ENABLE_PASS="${OLT_ENABLE_PASS:-}"
OLT_PROTO="${OLT_PROTO:-ssh}"
OLT_PORT="${OLT_PORT:-}"
CMD_FILE=""
DRY_RUN=0
TIMEOUT="${OLT_TIMEOUT:-25}"

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)     usage 0 ;;
        -c|--comandos) CMD_FILE="${2:?falta el archivo de comandos}"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        *) echo "Opcion desconocida: $1" >&2; usage 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Comandos de diagnostico.
#
# OJO: la sintaxis exacta cambia entre versiones de firmware de la 7001. Si un
# comando devuelve "Invalid command" NO es un problema: el script sigue con el
# siguiente y esa respuesta queda en el log, que ya nos dice cual es la sintaxis
# buena de tu equipo. Ajusta la lista o pasa la tuya con -c.
# ---------------------------------------------------------------------------
read -r -d '' COMANDOS_DEFAULT <<'CMDS'
# --- identidad y estado general ---
show system-info
show system resource
show running-config

# --- CAPA 1: puertos PON y optica ---
# ¿Estan los puertos administrativamente arriba? ¿Que potencia transmite la OLT?
show interface pon
show interface pon 1/0/1
show interface pon 1/0/1 transceiver-info
show interface pon 1/0/2 transceiver-info

# --- CAPA 2: ¿la OLT VE las ONUs? ---
# Esto es lo que parte el problema en dos:
#   sale algo -> problema de autenticacion/perfiles
#   sale vacio -> problema optico o de puerto
show onu unauth
show gpon onu-authentication-info
show gpon onu autofind

# --- CAPA 3: ONUs ya registradas y su estado ---
show onu all
show onu status
show gpon onu state
show onu optical-info

# --- CAPA 4: autenticacion y perfiles ---
# Causa #1 de "la detecta pero no sube": el modo de auth de la OLT (SN / LOID /
# LOID+password) no coincide con lo que trae la ONU de fabrica.
show gpon authentication-mode
show gpon profile line
show gpon profile service
show gpon profile dba

# --- CAPA 5: rastro de que paso ---
# Aqui salen los deregister, los rogue ONU y los flapeos.
show logging buffer
show logging
CMDS

if [ -n "$CMD_FILE" ]; then
    [ -r "$CMD_FILE" ] || { echo "ERROR: no puedo leer $CMD_FILE" >&2; exit 1; }
    COMANDOS="$(cat "$CMD_FILE")"
else
    COMANDOS="$COMANDOS_DEFAULT"
fi

# Quita comentarios y lineas vacias
COMANDOS_LIMPIOS="$(printf '%s\n' "$COMANDOS" | sed 's/#.*//' | sed '/^[[:space:]]*$/d')"

# ---------------------------------------------------------------------------
# Validacion de parametros
# ---------------------------------------------------------------------------
if [ -z "$OLT_HOST" ]; then
    read -r -p "IP de gestion de la OLT: " OLT_HOST
fi
[ -n "$OLT_HOST" ] || { echo "ERROR: falta OLT_HOST" >&2; exit 1; }

case "$OLT_PROTO" in
    ssh)    : "${OLT_PORT:=22}" ;;
    telnet) : "${OLT_PORT:=23}" ;;
    *) echo "ERROR: OLT_PROTO debe ser 'ssh' o 'telnet' (recibido: $OLT_PROTO)" >&2; exit 1 ;;
esac

SALIDA="diagnostico-olt-$(date +%Y%m%d-%H%M%S).txt"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "== DRY RUN =="
    echo "Destino : $OLT_USER@$OLT_HOST:$OLT_PORT ($OLT_PROTO)"
    echo "Salida  : $SALIDA"
    echo "Comandos a ejecutar:"
    printf '%s\n' "$COMANDOS_LIMPIOS" | sed 's/^/  /'
    exit 0
fi

# --- preflight: herramientas necesarias ---
faltantes=()
command -v expect  >/dev/null 2>&1 || faltantes+=("expect")
command -v "$OLT_PROTO" >/dev/null 2>&1 || faltantes+=("$OLT_PROTO")

if [ "${#faltantes[@]}" -gt 0 ]; then
    echo "ERROR: faltan estas herramientas: ${faltantes[*]}" >&2
    echo "Instalalas con:" >&2
    echo "  Debian/Ubuntu : sudo apt install ${faltantes[*]}" >&2
    echo "  RHEL/Rocky    : sudo dnf install ${faltantes[*]}" >&2
    echo "  macOS         : brew install ${faltantes[*]}" >&2
    exit 1
fi

# --- preflight: ¿la OLT responde en ese puerto? ---
# Falla aqui = problema de red/firewall/IP, no del script. Mejor saberlo antes.
if ! timeout 8 bash -c "cat < /dev/null > /dev/tcp/$OLT_HOST/$OLT_PORT" 2>/dev/null; then
    echo "ERROR: no hay respuesta en $OLT_HOST:$OLT_PORT ($OLT_PROTO)." >&2
    echo >&2
    echo "Revisa, en este orden:" >&2
    echo "  1. ping $OLT_HOST                     -> ¿llegas a la OLT?" >&2
    echo "  2. ¿estas en la VLAN/subred de gestion de la OLT?" >&2
    echo "  3. ¿la OLT tiene $OLT_PROTO habilitado? Muchas traen solo Telnet" >&2
    echo "     de fabrica: reintenta con OLT_PROTO=telnet" >&2
    echo "  4. ¿hay una ACL de gestion en la OLT que filtre tu IP?" >&2
    exit 1
fi

if [ -z "$OLT_PASS" ]; then
    read -r -s -p "Password de $OLT_USER en $OLT_HOST: " OLT_PASS
    echo
fi

# ---------------------------------------------------------------------------
# Sesion expect. La password viaja por variable de entorno, no por argv.
# ---------------------------------------------------------------------------
export OLT_HOST OLT_USER OLT_PASS OLT_ENABLE_PASS OLT_PROTO OLT_PORT TIMEOUT
export COMANDOS_LIMPIOS

echo "Conectando a $OLT_HOST:$OLT_PORT por $OLT_PROTO ..."

expect <<'EXPECT_EOF' > "$SALIDA" 2>&1
set host    $env(OLT_HOST)
set user    $env(OLT_USER)
set pass    $env(OLT_PASS)
set enpass  $env(OLT_ENABLE_PASS)
set proto   $env(OLT_PROTO)
set port    $env(OLT_PORT)
set timeout $env(TIMEOUT)
set cmds    [split [string trim $env(COMANDOS_LIMPIOS)] "\n"]

# Prompt tipico de la CLI TP-Link: algo terminado en > (user) o # (privilegiado)
set PROMPT {[\r\n][^\r\n]*[>#][ ]?$}

log_user 1
# Sin esto, los puts (cabeceras) y la salida del spawn salen con buffering
# distinto y el log queda desfasado un comando.
fconfigure stdout -buffering none

if {$proto eq "ssh"} {
    # KexAlgorithms/HostKeyAlgorithms viejos: las OLT suelen traer SSH antiguo
    spawn ssh -p $port \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 \
        -o HostKeyAlgorithms=+ssh-rsa,ssh-dss \
        -o PubkeyAuthentication=no \
        $user@$host
} else {
    spawn telnet $host $port
}

# --- login ---
set intentos 0
expect {
    -nocase -re {(user ?name|login)[: ]*$} {
        send -- "$user\r"
        exp_continue
    }
    -nocase -re {password[: ]*$} {
        # No dejamos rastro de la password en el log
        log_user 0
        send -- "$pass\r"
        log_user 1
        exp_continue
    }
    -nocase -re {(permission denied|authentication fail|login incorrect|bad password)} {
        puts "\n>>> ERROR: credenciales rechazadas por la OLT."
        exit 2
    }
    -re $PROMPT {
        # dentro
    }
    timeout {
        puts "\n>>> ERROR: timeout esperando el login. ¿La OLT responde en $host:$port?"
        puts ">>> Prueba primero:  ping $host   y   nc -vz $host $port"
        exit 3
    }
    eof {
        puts "\n>>> ERROR: la conexion se cerro antes del login."
        puts ">>> Si es SSH, la OLT puede tener cifrados muy viejos. Reintenta con OLT_PROTO=telnet."
        exit 4
    }
}

# --- modo privilegiado ---
send -- "enable\r"
expect {
    -nocase -re {password[: ]*$} {
        log_user 0
        if {$enpass eq ""} { send -- "$pass\r" } else { send -- "$enpass\r" }
        log_user 1
        exp_continue
    }
    -re $PROMPT {}
    timeout {}
}

# --- desactivar paginacion (probamos las variantes conocidas) ---
foreach nopag {"terminal length 0" "no terminal length" "screen-length 0 temporary" "terminal page 0"} {
    send -- "$nopag\r"
    expect { -re $PROMPT {} timeout {} }
}

# Drenar el residuo del buffer antes de empezar: si no, el primer comando
# matchea un prompt viejo y toda la salida queda corrida.
send -- "\r"
expect { -re $PROMPT {} timeout {} }

puts "\n"
puts "==============================================================="
puts " DIAGNOSTICO OLT TP-LINK  --  $host  --  [clock format [clock seconds]]"
puts "==============================================================="

# --- bateria de comandos ---
set sesion_viva 1
foreach cmd $cmds {
    set cmd [string trim $cmd]
    if {$cmd eq ""} continue

    puts "\n"
    puts "---------------------------------------------------------------"
    puts ">>> $cmd"
    puts "---------------------------------------------------------------"

    # Si la sesion ya murio, no tiene sentido seguir mandando comandos: sin
    # esto el log se llena de errores "spawn id not open" por cada comando.
    if {[catch {send -- "$cmd\r"} err]} {
        puts "\n>>> (sesion caida: $err)"
        puts ">>> Comandos no ejecutados a partir de aqui."
        set sesion_viva 0
        break
    }

    expect {
        # Paginador que se colo pese al terminal length 0
        -nocase -re {--+ ?more ?--+|\(q\)uit|press any key} {
            send -- " "
            exp_continue
        }
        -re $PROMPT {}
        timeout {
            puts "\n>>> (timeout en este comando, sigo con el siguiente)"
            # Ctrl-C para abortar el comando colgado. Si la sesion ya no esta,
            # catch evita que reviente el resto del recorrido.
            if {[catch {send -- "\003"}]} {
                puts ">>> (la sesion se cerro al abortar)"
                set sesion_viva 0
                break
            }
            expect { -re $PROMPT {} timeout {} eof { set sesion_viva 0 } }
            if {!$sesion_viva} { break }
        }
        eof {
            puts "\n>>> (la OLT cerro la sesion)"
            set sesion_viva 0
            break
        }
    }
}

puts "\n"
puts "==============================================================="
puts " FIN DEL DIAGNOSTICO"
puts "==============================================================="

if {$sesion_viva} {
    catch {send -- "exit\r"}
    catch {expect eof}
}
# El estado del cliente telnet/ssh al cerrar no dice nada sobre si el
# diagnostico se recolecto bien.
exit 0
EXPECT_EOF

RC=$?

# Red de seguridad: por si alguna variante de firmware llega a eco-ar la password
if [ -n "$OLT_PASS" ] && [ -f "$SALIDA" ]; then
    python3 - "$SALIDA" <<'PY' 2>/dev/null || sed -i.bak "s/$(printf '%s' "$OLT_PASS" | sed 's/[][\.*^$/]/\\&/g')/***REDACTADO***/g" "$SALIDA" 2>/dev/null
import os, sys
p = sys.argv[1]
pw = os.environ.get("OLT_PASS", "")
if pw:
    with open(p, "r", errors="replace") as f: t = f.read()
    with open(p, "w") as f: f.write(t.replace(pw, "***REDACTADO***"))
PY
    rm -f "$SALIDA.bak"
fi

echo
if [ "$RC" -eq 0 ]; then
    echo "OK. Diagnostico guardado en: $SALIDA"
else
    echo "La sesion termino con codigo $RC. Revisa igual el archivo: $SALIDA"
fi
echo
echo "Revisa el archivo antes de compartirlo (lleva tu running-config)."
echo "Lo importante para el diagnostico son estas secciones:"
echo "  - show onu unauth / autofind   -> ¿la OLT ve las ONUs?"
echo "  - transceiver-info             -> ¿hay luz y en que nivel?"
echo "  - show logging                 -> deregister, rogue ONU, flapeos"
exit "$RC"
