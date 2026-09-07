# ============================================================================
# EVG-CALIBRA -- VARIANTE COMPAT (sin arrays asociativos)   para EVG-FW2026 v7.14
# ============================================================================
#
#  QUE ES
#    Un reemplazo de la SECCION 9.9 (EVG-CALIBRA) que NO usa arrays
#    asociativos de RouterOS -- ni ($arr->clave) ni ':foreach k,v'. Sirve por
#    si tu version/build de ROS se queja de esos constructos con la version
#    normal. Hace lo MISMO (mismos objetivos y mismas listas), con otros
#    metodos mas compatibles:
#
#      - UMBRAL DE CONEXIONES (6B.5): por REALIMENTACION de la lista, sin
#        escanear conexiones. Si hay clientes en CPE-CONNFLOOD que NO estan
#        confirmados (presuntos legitimos), sube el umbral; si no hay ninguno,
#        lo baja de a poco hacia el piso. Acotado a [EVGCONNFLOORMIN, MAX] y
#        leido de la propia regla (sobrevive reboot). El DROP de 6B.5 sigue
#        deshabilitado, asi que esto NUNCA corta a un cliente.
#
#      - PROXY (FP-04): cuenta flujos grandes y simetricos POR EQUIPO usando
#        el 'comment' de una lista temporal como contador (no array asoc).
#        Marca a CPE-PROXY solo con >= EVGPROXYMINFLOWS flujos a la vez.
#
#      - DoT (FP-02): cuenta por destino :853 usando el 'comment' como
#        contador. OJO: en COMPAT cuenta CONEXIONES al resolver, no clientes
#        DISTINTOS (para eso hace falta la version con arrays asoc). Un
#        resolver legitimo tiene muchas conexiones; un C2 de un solo bot,
#        pocas -- asi que sigue sirviendo, pero es una aproximacion. El
#        bloqueo OPT-DOT esta apagado, o sea que solo afecta a una lista de
#        deteccion. Alternativa 100% a mano: mirar CENSO-DOT y promover el
#        resolver que veas usado por varios:
#          /ip firewall address-list add list=DNS-OK address=<ip> comment="manual"
#
#      - EVG-NO-AUTOBLOCK (FP-03) y CORROBORACION 6969 (FP-01): igual que en
#        la version normal (esas partes ya no usaban arrays asociativos).
#
#  COMO SE USA
#    1) Aplicar primero el script principal EVG-FW2026-v7.14.rsc completo.
#    2) Pegar ESTE archivo despues. Quita el EVG-CALIBRA normal (script +
#       scheduler), instala esta variante, la agenda cada hora y la corre una
#       vez. No toca ninguna otra regla.
#    3) Revisar:  /log print where message~"EVG-CALIBRA"
#
#  Para volver a la version normal: reaplicar EVG-FW2026-v7.14.rsc (su
#  SECCION 0 limpia EVG-CALIBRA y reinstala la version con arrays asoc).
# ============================================================================

:log warning "EVG-CALIBRA(compat): instalando variante sin arrays asociativos"

# --- quitar el EVG-CALIBRA anterior (script + scheduler) --------------------
/system scheduler
:if ([:len [find name="EVG-CALIBRA"]] > 0) do={ remove [find name="EVG-CALIBRA"] }
/system script
:if ([:len [find name="EVG-CALIBRA"]] > 0) do={ remove [find name="EVG-CALIBRA"] }

# --- instalar la variante COMPAT -------------------------------------------
/system script
add name=EVG-CALIBRA owner=admin policy=read,write,test source={
# defaults reboot-safe: los globales se pierden en reboot; aqui se re-siembran
# si faltan (el valor aprendido igual queda guardado en la REGLA).
:global EVGCONNFLOOD;      :if ([:typeof $EVGCONNFLOOD]      != "num") do={ :set EVGCONNFLOOD 800 }
:global EVGCONNFLOORMIN;   :if ([:typeof $EVGCONNFLOORMIN]   != "num") do={ :set EVGCONNFLOORMIN 400 }
:global EVGCONNFLOORMAX;   :if ([:typeof $EVGCONNFLOORMAX]   != "num") do={ :set EVGCONNFLOORMAX 4000 }
:global EVGPROXYMINMB;     :if ([:typeof $EVGPROXYMINMB]     != "num") do={ :set EVGPROXYMINMB 40 }
:global EVGPROXYFACTOR;    :if ([:typeof $EVGPROXYFACTOR]    != "num") do={ :set EVGPROXYFACTOR 2 }
:global EVGPROXYMINFLOWS;  :if ([:typeof $EVGPROXYMINFLOWS]  != "num") do={ :set EVGPROXYMINFLOWS 4 }
:global EVGDOTMINCLIENTES; :if ([:typeof $EVGDOTMINCLIENTES] != "num") do={ :set EVGDOTMINCLIENTES 5 }
:global EVGCONNMAXSCAN;    :if ([:typeof $EVGCONNMAXSCAN]    != "num") do={ :set EVGCONNMAXSCAN 60000 }

:local minB ($EVGPROXYMINMB * 1048576)
:local factor $EVGPROXYFACTOR
:log info "EVG-CALIBRA(compat): inicio"

# ---- (4) EVG-NO-AUTOBLOCK: union de infra de confianza  [FP-03] -----------
/ip firewall address-list remove [find where list="EVG-NO-AUTOBLOCK" and comment~"EVG-AUTO"]
:foreach L in={"GATEWAYS";"BGP-PEERS";"DNS-OK";"IP-PUBLICA";"WAN-PRIVADA"} do={
  :foreach e in=[/ip firewall address-list find where list=$L] do={
    :do {
      :local ad [/ip firewall address-list get $e address]
      :if ($ad != "127.0.0.1") do={
        :if ([:len [/ip firewall address-list find where list="EVG-NO-AUTOBLOCK" and address=$ad]] = 0) do={
          /ip firewall address-list add list="EVG-NO-AUTOBLOCK" address=$ad comment="EVG-AUTO union infra"
        }
      }
    } on-error={}
  }
}

# ---- (5) correlacion 6969: escalar SOSPECHA a CONFIRMADO  [FP-01] ---------
:local escalados 0
:foreach s in=[/ip firewall address-list find where list="CPE-MIRAI-SOSPECHA"] do={
  :do {
    :local ip [/ip firewall address-list get $s address]
    :local dura false
    :foreach L in={"CPE-INFECTADO";"CPE-IOT-PROPAGA";"CPE-IOT-LATERAL"} do={
      :if ([:len [/ip firewall address-list find where list=$L and address=$ip]] > 0) do={ :set dura true }
    }
    :if ($dura) do={
      :if ([:len [/ip firewall address-list find where list="CPE-INFECTADO" and address=$ip]] = 0) do={
        :do { /ip firewall address-list add list=CPE-INFECTADO address=$ip timeout=30d comment="EVG-CALIBRA 6969 corroborado por señal dura" } on-error={}
      }
      :if ([:len [/ip firewall address-list find where list="CPE-MIRAI-C2" and address=$ip]] = 0) do={
        :do { /ip firewall address-list add list=CPE-MIRAI-C2 address=$ip timeout=30d comment="EVG-CALIBRA 6969 corroborado" } on-error={}
      }
      :log warning ("EVG-CALIBRA(compat): 6969 CORROBORADO -> " . $ip . " -> CONFIRMADO")
      :set escalados ($escalados + 1)
    }
  } on-error={}
}

# ---- (1) UMBRAL DE CONEXIONES por REALIMENTACION (sin escaneo) ------------
# Leer el umbral actual DESDE LA REGLA (persiste en config, sobrevive reboot).
:local actual $EVGCONNFLOORMIN
:do {
  :local s [:tostr [/ip firewall filter get [find where comment~"DETECTA exceso de conexiones"] connection-limit]]
  :local com [:find $s ","]
  :if ([:typeof $com] = "num") do={ :set actual [:tonum [:pick $s 0 $com]] }
} on-error={}

# Contar clientes flagged que NO estan en ninguna lista dura = presuntos
# legitimos que el umbral esta marcando de mas.
:local legit 0
:local flagged [:len [/ip firewall address-list find where list="CPE-CONNFLOOD"]]
:foreach f in=[/ip firewall address-list find where list="CPE-CONNFLOOD"] do={
  :do {
    :local ip [/ip firewall address-list get $f address]
    :local malo false
    :foreach L in={"CPE-INFECTADO";"CPE-MIRAI-C2";"CPE-IOT-PROPAGA";"CPE-IOT-LATERAL"} do={
      :if ([:len [/ip firewall address-list find where list=$L and address=$ip]] > 0) do={ :set malo true }
    }
    :if (!$malo) do={ :set legit ($legit + 1) }
  } on-error={}
}

:local nuevo $actual
:if ($legit > 0) do={
  # se marcan clientes legitimos -> subir el umbral (x1.5)
  :set nuevo (($actual * 3) / 2)
} else={
  # nadie flagged en absoluto -> bajar suave hacia el piso (x0.9). Seguro
  # porque el DROP de 6B.5 esta deshabilitado.
  :if ($flagged = 0) do={ :set nuevo (($actual * 9) / 10) }
}
:if ($nuevo < $EVGCONNFLOORMIN) do={ :set nuevo $EVGCONNFLOORMIN }
:if ($nuevo > $EVGCONNFLOORMAX) do={ :set nuevo $EVGCONNFLOORMAX }
:if ($nuevo != $actual) do={
  :set EVGCONNFLOOD $nuevo
  :do { /ip firewall filter set [find where comment~"DETECTA exceso de conexiones"] connection-limit=("$nuevo,32") } on-error={}
  :do { /ip firewall filter set [find where comment~"OPT-CONEXIONES"] connection-limit=("$nuevo,32") } on-error={}
  :log warning ("EVG-CALIBRA(compat): umbral conexiones " . $actual . " -> " . $nuevo . " (legit flagged=" . $legit . " / total flagged=" . $flagged . ")")
} else={
  :set EVGCONNFLOOD $actual
  :log info ("EVG-CALIBRA(compat): umbral conexiones se mantiene en " . $actual . " (legit=" . $legit . " total=" . $flagged . ")")
}

# ---- pasada UNICA por conexiones: (2) proxy y (3) DoT ---------------------
# Contadores por clave guardados en el 'comment' de listas temporales, en vez
# de arrays asociativos. Se limpian al inicio y al final.
/ip firewall address-list remove [find where list="EVG-CAL-SYM"]
/ip firewall address-list remove [find where list="EVG-CAL-DOT"]

:local nConn [:len [/ip firewall connection find]]
:if ($nConn > $EVGCONNMAXSCAN) do={
  :log warning ("EVG-CALIBRA(compat): " . $nConn . " conexiones (> EVGCONNMAXSCAN=" . $EVGCONNMAXSCAN . "). Se OMITE el escaneo de proxy/DoT para no clavar la CPU.")
} else={
  :local nProxy 0
  :foreach c in=[/ip firewall connection find where protocol="tcp"] do={
    :do {
      :local sa [:tostr [/ip firewall connection get $c src-address]]
      :local cp [:find $sa ":"]
      :local ip $sa
      :if ([:typeof $cp] = "num") do={ :set ip [:pick $sa 0 $cp] }

      # --- (2) proxy por simetria: contador por src en el comment ---
      :local ob [/ip firewall connection get $c orig-bytes]
      :local rb [/ip firewall connection get $c repl-bytes]
      :if (($ob > $minB) and ($rb > $minB)) do={
        :local hi $ob
        :local lo $rb
        :if ($rb > $ob) do={ :set hi $rb; :set lo $ob }
        :if (($lo * $factor) > $hi) do={
          :if ([:len [/ip firewall address-list find where list="CPE-PROXY" and address=$ip]] = 0) do={
            :local idS [/ip firewall address-list find where list="EVG-CAL-SYM" and address=$ip]
            :if ([:len $idS] = 0) do={
              :do { /ip firewall address-list add list=EVG-CAL-SYM address=$ip comment="1" } on-error={}
            } else={
              :local n 1
              :do { :set n [:tonum [/ip firewall address-list get $idS comment]] } on-error={ :set n 1 }
              :set n ($n + 1)
              :if ($n >= $EVGPROXYMINFLOWS) do={
                :do {
                  /ip firewall address-list add list=CPE-PROXY address=$ip timeout=7d comment="EVG-PROXY-DATA multi-flujo simetrico"
                  /ip firewall address-list remove $idS
                  :set nProxy ($nProxy + 1)
                  :log warning ("EVG-CALIBRA(compat): posible proxy " . $ip . " (>= " . $EVGPROXYMINFLOWS . " flujos grandes simetricos)")
                } on-error={}
              } else={
                :do { /ip firewall address-list set $idS comment="$n" } on-error={}
              }
            }
          }
        }
      }

      # --- (3) DoT: contador de conexiones por destino :853 ---
      :local da [:tostr [/ip firewall connection get $c dst-address]]
      :local dcp [:find $da ":"]
      :if ([:typeof $dcp] = "num") do={
        :if ([:pick $da ($dcp + 1) [:len $da]] = "853") do={
          :local dip [:pick $da 0 $dcp]
          :if ([:len [/ip firewall address-list find where list="DNS-OK" and address=$dip]] = 0) do={
            :local idD [/ip firewall address-list find where list="EVG-CAL-DOT" and address=$dip]
            :if ([:len $idD] = 0) do={
              :do { /ip firewall address-list add list=EVG-CAL-DOT address=$dip comment="1" } on-error={}
            } else={
              :local m 1
              :do { :set m [:tonum [/ip firewall address-list get $idD comment]] } on-error={ :set m 1 }
              :set m ($m + 1)
              :do { /ip firewall address-list set $idD comment="$m" } on-error={}
            }
          }
        }
      }
    } on-error={}
  }

  # --- DoT: promover a DNS-OK los destinos con muchas conexiones ---
  :local nDot 0
  :foreach d in=[/ip firewall address-list find where list="EVG-CAL-DOT"] do={
    :do {
      :local dip [/ip firewall address-list get $d address]
      :local m 0
      :do { :set m [:tonum [/ip firewall address-list get $d comment]] } on-error={ :set m 0 }
      :if ($m >= $EVGDOTMINCLIENTES) do={
        :if ([:len [/ip firewall address-list find where list="DNS-OK" and address=$dip]] = 0) do={
          :do {
            /ip firewall address-list add list=DNS-OK address=$dip timeout=30d comment=("EVG-AUTO DoT " . $m . " conexiones")
            :set nDot ($nDot + 1)
            :log info ("EVG-CALIBRA(compat): DoT " . $dip . " con " . $m . " conexiones -> DNS-OK (aprox por conexiones, no clientes)")
          } on-error={}
        }
      }
    } on-error={}
  }
  :log info ("EVG-CALIBRA(compat): conexiones=" . $nConn . " proxies-nuevos=" . $nProxy . " DoT-nuevos=" . $nDot)
}

# limpiar contadores temporales
/ip firewall address-list remove [find where list="EVG-CAL-SYM"]
/ip firewall address-list remove [find where list="EVG-CAL-DOT"]

:log warning ("EVG-CALIBRA(compat): fin | umbral-conexiones=" . $EVGCONNFLOOD . " | 6969-escalados=" . $escalados . " | no-autobloqueo=" . [:len [/ip firewall address-list find where list="EVG-NO-AUTOBLOCK"]])
}

# --- agendar cada hora y correr una vez ------------------------------------
/system scheduler
add name=EVG-CALIBRA on-event=EVG-CALIBRA interval=1h start-time=startup policy=read,write,test comment="EVG-FW2026 | Autocalibracion (variante COMPAT sin arrays asociativos)"
/system script run EVG-CALIBRA
:log warning "EVG-CALIBRA(compat): instalada y ejecutada. Revisar: /log print where message~\"EVG-CALIBRA\""
