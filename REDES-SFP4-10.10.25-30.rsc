# ============================================================================
# CREAR REDES 10.10.25.0/24 .. 10.10.30.0/24 EN sfp-sfpplus4   (RouterOS 7.x)
# ============================================================================
#
#  QUE HACE
#    Agrega 6 direcciones IP (una por cada /24) sobre la MISMA interfaz fisica
#    sfp-sfpplus4, dejando al router como gateway de cada red:
#
#      10.10.25.1/24   ->  red 10.10.25.0/24   (hosts .2 - .254)
#      10.10.26.1/24   ->  red 10.10.26.0/24
#      10.10.27.1/24   ->  red 10.10.27.0/24
#      10.10.28.1/24   ->  red 10.10.28.0/24
#      10.10.29.1/24   ->  red 10.10.29.0/24
#      10.10.30.1/24   ->  red 10.10.30.0/24
#
#    NOTA SOBRE EL RANGO PEDIDO: se pidio "de 10.10.25.2/24 hasta
#    10.10.30.1/24". Esas dos son direcciones de HOST dentro de dos redes /24
#    distintas; las redes que las contienen son 10.10.25.0/24 y 10.10.30.0/24,
#    y esas son las que crea el script (con las 4 intermedias). El ultimo
#    octeto que toma el ROUTER se controla con la variable "hostOct":
#      hostOct=1  -> 10.10.25.1 ... 10.10.30.1   (default, convencion gateway)
#      hostOct=2  -> 10.10.25.2 ... 10.10.30.2   (si queres el .2 literal)
#
#  ES SEGURO CORRERLO VARIAS VECES
#    Si la direccion ya existe en esa interfaz, la saltea (no duplica).
#    Si la MISMA direccion existe en OTRA interfaz, avisa y no toca nada.
#
#  COMO SE USA
#    Opcion A (pegar en terminal):  copiar y pegar el bloque completo.
#    Opcion B (archivo):            subir el .rsc por Files y ejecutar:
#                                     /import file-name=REDES-SFP4-10.10.25-30.rsc
#
#  AL FINAL DEL ARCHIVO hay dos bloques opcionales:
#    - DESHACER  : borra exactamente lo que agrego este script.
#    - VARIANTE VLAN: si en realidad queres las 6 redes SEPARADAS (una VLAN
#      por red) sobre el mismo sfp-sfpplus4, en vez de 6 IP en la misma LAN.
# ============================================================================

# ------------------------- CONFIGURACION ------------------------------------
:local iface   "sfp-sfpplus4";   # interfaz donde se agregan las direcciones
:local base    "10.10.";         # los dos primeros octetos
:local desde   25;               # tercer octeto inicial
:local hasta   30;               # tercer octeto final
:local hostOct 1;                # ultimo octeto del router en cada red (1 o 2)
:local mask    "/24";
:local tag     "AUTO-REDES-SFP4";# comentario con el que se marcan las IP
# ----------------------------------------------------------------------------

:local ok 0;
:local skip 0;
:local err 0;

:put "== CREAR REDES EN $iface ==";

# 1) La interfaz tiene que existir
:if ([:len [/interface find name=$iface]] = 0) do={
    :put "ERROR: no existe la interfaz $iface. Reviso el nombre con /interface print";
    :error "interfaz inexistente: $iface";
}

# 2) Alta de una direccion por cada red del rango
:for i from=$desde to=$hasta do={
    :local red  ($base . $i . ".0" . $mask);
    :local dir  ($base . $i . "." . $hostOct . $mask);
    :local yaEnIface [/ip address find address=$dir interface=$iface];
    :local yaEnOtra  [/ip address find address=$dir];

    :if ([:len $yaEnIface] > 0) do={
        :set skip ($skip + 1);
        :put "  = YA EXISTE  $dir en $iface (no se toca)";
    } else={
        :if ([:len $yaEnOtra] > 0) do={
            :local otra [/ip address get [:pick $yaEnOtra 0] interface];
            :set err ($err + 1);
            :put "  ! CONFLICTO  $dir ya esta en la interfaz $otra -- se omite";
        } else={
            :do {
                /ip address add address=$dir interface=$iface comment="$tag red $red";
                :set ok ($ok + 1);
                :put "  + AGREGADA   $dir  (red $red)";
            } on-error={
                :set err ($err + 1);
                :put "  ! ERROR al agregar $dir";
            }
        }
    }
}

:put "== RESUMEN: agregadas=$ok  ya existian=$skip  con problema=$err ==";
:put "Verificar con:  /ip address print where interface=$iface";

# ============================================================================
#  DESHACER  (borra SOLO lo que agrego este script, por el comentario)
# ============================================================================
#  /ip address remove [find comment~"^AUTO-REDES-SFP4"]

# ============================================================================
#  VARIANTE VLAN  (opcional -- 6 redes SEPARADAS sobre el mismo sfp-sfpplus4)
# ============================================================================
#  El bloque de arriba pone las 6 IP en la MISMA LAN fisica: todos los equipos
#  conectados se ven entre si en capa 2. Si lo que queres es una red aislada
#  por cada /24 (VLAN 25..30 etiquetadas sobre sfp-sfpplus4), corre ESTO en
#  lugar del bloque de arriba (y ajusta los VLAN ID si tu switch usa otros):
#
#  :local iface "sfp-sfpplus4";
#  :local base "10.10.";
#  :local hostOct 1;
#  :for i from=25 to=30 do={
#      :local vname ("vlan" . $i);
#      :local dir ($base . $i . "." . $hostOct . "/24");
#      :if ([:len [/interface vlan find name=$vname]] = 0) do={
#          /interface vlan add name=$vname vlan-id=$i interface=$iface \
#              comment="AUTO-REDES-SFP4 vlan $i";
#      }
#      :if ([:len [/ip address find address=$dir interface=$vname]] = 0) do={
#          /ip address add address=$dir interface=$vname \
#              comment=("AUTO-REDES-SFP4 red " . $base . $i . ".0/24");
#      }
#      :put ("listo " . $vname . " -> " . $dir);
#  }
#
#  Deshacer la variante VLAN:
#    /ip address remove [find comment~"^AUTO-REDES-SFP4"]
#    /interface vlan remove [find comment~"^AUTO-REDES-SFP4"]
# ============================================================================
