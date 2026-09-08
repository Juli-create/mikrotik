# ============================================================================
# EVG-QOS2026-R6 | QoS ISP CONSOLIDADO (RouterOS 7.x)
# ============================================================================
# Objetivo: que el QoS NO interfiera con la medicion del cliente (Ookla, Fast,
# nPerf, servidor on-net) y que sea aplicable en PPPoE, IPoE, VLAN o bridge sin
# reescribir el script.
#
# R6 es una REVISION de R5: misma arquitectura, mismas clases, mismo tag de
# idempotencia. Lo que cambia son bugs que abortaban el import, costo de CPU y
# tres supuestos del R5 que no se sostienen contra la implementacion real de
# CAKE ni contra el flujo de paquetes de RouterOS.
#
# ---------------------------------------------------------------------------
# CAMBIOS vs R5   (los cuatro primeros son BUGS, no mejoras opinables)
# ---------------------------------------------------------------------------
#
#  [R6-01] *** cake-nat=si ABORTA EL IMPORT ***
#          R5 declara  :global EVGNAT "no"  y documenta que hay que ponerlo en
#          "si" cuando una cola agrupa varios clientes. Ese valor se pasa TAL
#          CUAL a  cake-nat=$EVGNAT. RouterOS espera yes/no: con "si" el add
#          del queue type falla, y como el import corta en el primer error, el
#          script muere DESPUES de la SECCION 1 (que ya borro todo el QoS
#          anterior). Es decir: el unico cambio que R5 pide hacer a mano deja
#          al equipo sin QoS.
#          R6 traduce si/no/yes/no y ademas acepta EVGNAT="auto": mira si hay
#          colas cuyo target es una red y/o src-nat de clientes, y decide.
#
#  [R6-02] *** UN SOLO ERROR TIRA TODO EL SCRIPT ***
#          Mismo problema, general: /import aborta en el primer comando que
#          falla, y la limpieza idempotente corre PRIMERO. Cualquier propiedad
#          no soportada por el build (tls-host en /ipv6 firewall mangle,
#          interface-list en /ppp profile, cake-ack-filter en builds viejos)
#          deja el router SIN QoS y sin aviso claro.
#          R6 envuelve cada bloque en :do{}on-error={} , cuenta las fallas en
#          $EVGERR y las reporta al final. Peor caso: se pierde UN bloque, no
#          la configuracion entera.
#
#  [R6-03] *** immediate-gw SIN "%" SE DESCARTABA (PPPoE-client, tuneles) ***
#          R5 exige que immediate-gw tenga "%" para sacar la interfaz. En una
#          ruta punto a punto (pppoe-out1, l2tp-out1, wg) el campo es SOLO el
#          nombre de la interfaz, sin "%": ese uplink nunca entraba a la lista
#          WAN. Y con ECMP (dos salidas) el campo trae varios next-hop
#          separados por coma; R5 tomaba desde el primer "%" hasta el FINAL de
#          la cadena, o sea un nombre inexistente, y perdia las dos.
#          R6 parte por comas y trata el "%" como opcional. Ademas descubre
#          WAN por la ruta por defecto IPv6 (::/0).
#
#  [R6-04] *** $EVGELEBYTES NUNCA SE USABA ***
#          La variable existe y esta documentada, pero las tres reglas de
#          elefante llevan 250000000 escrito a mano (IPv4, IPv6 y la variante
#          habilitada). Cambiar la variable no cambiaba nada.
#
#  [R6-05] *** CAKE-WASH: R5 CONFUNDE DOS LAVADOS DISTINTOS ***
#          R5 pone cake-wash=no y lo justifica con "el wash lo hacemos nosotros
#          en mangle". Son cosas distintas:
#            - el wash de mangle es de INGRESO: borra el DSCP que TRAE el
#              paquete (del cliente o de internet) para que nadie se cuele.
#            - cake-wash es de EGRESO: CAKE elige el tin con el DSCP y DESPUES
#              lo pone en 0 al entregar el paquete.
#          Con cake-wash=no el DSCP que ponemos nosotros SALE del router:
#            hacia el cliente -> el CPE lo mapea a WMM. AF11 (YouTube) cae en
#              AC_BK y CS1 (bulk) tambien: en un WiFi cargado el video queda
#              detras de todo. Es una causa mucho mas probable de "se pega"
#              que la regla de elefante.
#            hacia el upstream -> le exportamos nuestra politica interna a un
#              transito que puede tener su propia policia por DSCP.
#          R6 usa cake-wash=yes por defecto ($EVGWASH). La clasificacion no
#          cambia: CAKE ya eligio el tin ANTES de lavar.
#
#  [R6-06] *** EL MAPEO CS1 -> tin 0 DEPENDE DE LA VERSION DE CAKE ***
#          La tabla que R5 da por cierta es la de cake 2017:
#             diffserv8[8] = 0   -> CS1 al tin 0 (Background)
#          En cake moderno esa fila cambio con RFC 8622 (LE):
#             diffserv8[1] = 0   -> LE (DSCP 1) al tin 0
#             diffserv8[8] = 1   -> CS1 al tin 1, JUNTO CON AF1x
#          Segun que build de CAKE lleve tu RouterOS, BULK (CS1) cae en tin 0
#          o comparte tin con STREAMING (AF11). No es catastrofico -- los dos
#          estan por debajo de best effort -- pero la separacion
#          "actualizaciones abajo de todo" puede no existir.
#          NO se arregla poniendo DSCP 1: en la tabla vieja el DSCP 1 va al
#          tin 5 (Interactive Shell), o sea las actualizaciones subirian a la
#          clase de latencia critica. R6 deja CS1, expone $EVGDSCPBULK y
#          documenta como verificarlo en tu equipo (ver COMPROBACION DE TIN).
#
#  [R6-07] *** COSTO DE CPU: SE EVALUABAN ~50 REGLAS POR PAQUETE ***
#          Este es el cambio que mas se nota en un nodo cargado.
#          En R5 TODO paquete de cliente recorre las ~45 reglas de
#          mark-connection hasta que alguna matchea; las de trafico ya
#          establecido (la enorme mayoria de los paquetes) las recorren TODAS
#          para terminar descartadas por connection-state=new. Lo mismo en raw:
#          ~60 reglas tls-host evaluadas por cada paquete, sea o no 443.
#          R6 mete todo en CADENAS PROPIAS con una sola regla de entrada:
#            raw prerouting  -> jump EVG-SNI      solo tcp dst-port 443/80
#            mangle prerout. -> jump EVG-SNILIVE  solo tcp/443 primeros 20 KB
#            mangle prerout. -> jump EVG-MARK     solo connection-state=new
#          Un paquete de una descarga en curso pasa de ~45 evaluaciones a 3.
#          El resultado es identico; cambia el costo.
#
#  [R6-08] *** RANGOS ANCHOS DE GAMING: DEGRADACION POR VOLUMEN ***
#          R5 avisa del riesgo (un flujo pesado que cae en tin 5 o 6 se
#          autocastiga) y lo deja documentado, nada mas. R6 lo resuelve: una
#          partida son kilobytes por minuto; una descarga por el mismo puerto
#          son cientos de MB. Si una conexion marcada GAMING pasa de
#          $EVGGAMERATE, o una CONTROL-CRITICO (rango RTP 16000-17000) pasa de
#          $EVGEFRATE, se le devuelve DSCP 0 (tin 2, que no tiene techo).
#          Es lo contrario de la regla de elefante: no castiga, DESASCIENDE a
#          best effort algo que estaba mal clasificado. Y como se mide por TASA
#          y no por bytes acumulados, es REVERSIBLE: cuando el flujo baja,
#          vuelve solo a su clase.
#
#  [R6-09] *** GUARDAS QUE FALTABAN Y APAGAN EL QoS SIN AVISO ***
#          - conntrack en "no": TODAS las reglas connection-mark son papel
#            pintado. Aborta.
#          - bridge con use-ip-firewall=no: si los clientes se puentean entre
#            si, ese trafico NO pasa por mangle. Avisa.
#          - BYPASS-RAW de EVG-FW2026 habilitado: corta el raw y las listas
#            por SNI dejan de poblarse. Avisa.
#          - IPv6 sin cola: ver [R6-10].
#
#  [R6-10] *** IPv6 SE CLASIFICA PERO NO SE CONFORMA ***
#          R5 hace un espejo completo en IPv6 (raw + mangle + DSCP). Pero la
#          cola simple dinamica que crea PPP tiene como target la IP v4 del
#          cliente: el trafico IPv6 NO ENTRA A ESA COLA. Es decir, se clasifica
#          con todo detalle trafico que despues sale SIN SHAPING -- el cliente
#          con IPv6 no tiene plan.
#          R6 lo detecta (hay IPv6 global o DHCPv6-PD y ninguna cola con target
#          IPv6) y lo grita en el log, con las dos salidas posibles
#          documentadas al final del archivo.
#
#  [R6-11] Reglas de output acotadas con out-interface-list=$EVGCLILIST: R5
#          marcaba EF todo el DNS/ICMP que sale del router, tambien hacia el
#          upstream. Ademas se agregan las que faltaban (DNS TCP v6, DoT,
#          Winbox saliente del router).
#
#  [R6-12] Limpieza: R5 no tocaba /ipv6 firewall address-list ni las entradas
#          DINAMICAS que dejan las reglas raw (no llevan comentario, asi que el
#          borrado por tag no las ve). Al cambiar de version quedaban IPs
#          clasificando con criterios viejos hasta 12 h.
#
#  [R6-13] Nombres de address-list sin espacios ("HBO MAX" -> HBO-MAX, etc).
#          Un nombre con espacio obliga a comillas en todos lados y es el
#          origen tipico del mismo bug que R5 arreglo en el queue type.
#
#  [R6-14] /ppp profile queue-type: R5 escribe "EVG-CAKE2026/EVG-CAKE2026". Ese
#          formato par es el de /queue simple. R6 intenta primero el nombre
#          simple y solo si falla prueba el par, y avisa si no pudo.
#
#  [R6-15] EVG-QOS-COLAS tambien engancha los ppp profile nuevos (el facturador
#          crea perfiles, no solo colas) y EVG-QOS-REPORT verifica coherencia
#          overhead/mpu, colas sin max-limit e IPv6 sin cola.
#
#  [R6-16] $EVGPURGA: purga opcional y automatica de las conexiones sin marca
#          al terminar. Sin eso, todo lo que ya estaba abierto sigue sin
#          clasificar hasta que expire, y el primer reporte miente.
#
#  [R6-17] En modo CPU bajo no se cargan las listas SNI largas (BULK y social).
#          El ahorro real de ese modo esta en NO evaluar reglas por paquete,
#          no en diffserv4 (elegir el tin es una lectura de tabla: no cuesta).
#
# ---------------------------------------------------------------------------
# LO QUE R5 YA TENIA BIEN Y R6 CONSERVA SIN TOCAR
# ---------------------------------------------------------------------------
#   - Autodescubrimiento con borrado selectivo por tag EVG-QOS2026-AUTO.
#   - La formula de overhead y las dos escuelas (18/38) con su MPU (64/84).
#   - Speedtest en tin 2 y no en tin 6.
#   - Reclasificacion por SNI en vivo para el primer flujo.
#   - Regla de elefante creada pero deshabilitada.
#   - 5060/TCP fuera del match de speedtest.
#   - Redes sociales en tin 2 junto con la web.
#
# ---------------------------------------------------------------------------
# IDEMPOTENTE: reaplicable sin duplicar. Tag "EVG-QOS2026" (borra R2..R5).
# ---------------------------------------------------------------------------
# *** COMO APLICARLO ***
#   1. Exportar antes:  /export file=antes-qos
#   2. Subir este .rsc por Files (Winbox: arrastrar al panel Files)
#   3. /import file-name=EVG-QOS2026-R6.rsc
#   4. /log print where message~"EVG-QOS2026"
#      -> la ULTIMA linea dice cuantos bloques fallaron. Si no es 0, leer.
#
# Si lo pegas en terminal: COMPLETO de una sola vez, nunca por pedazos.
# Todas las variables de control son :global justamente por eso.
# ============================================================================


# ============================================================================
# MAPEO DE diffserv8 EN CAKE  (fuente: gen_cake_const.c, diffserv8())
# ============================================================================
# tin 7  CS6(48) CS7(56)                        Network Control
# tin 6  EF(46) VA(44) CS5(40) CS4(32)          Minimum Latency
# tin 5  CS2(16)                                Interactive Shell
# tin 4  AF2x(18,20,22) TOS4(4)                 Low Latency Transactions
# tin 3  AF3x(26,28,30) AF4x(34,36,38) CS3(24)  Video Streaming
# tin 2  CS0(0) y todo lo no listado            Bog Standard  (umbral 100%)
# tin 1  AF1x(10,12,14)  [y CS1(8) en cake nuevo]   High Throughput
# tin 0  CS1(8) en cake viejo / LE(1) en cake nuevo  Background   [R6-06]
#
# *** ADVERTENCIA DE DISEÑO QUE HAY QUE ENTENDER ANTES DE TOCAR ESTO ***
# En CAKE los tines NO son colas de prioridad estricta: cada tin tiene un
# UMBRAL de banda. Un tin ALTO tiene umbral BAJO. Es decir, mandar trafico
# pesado a tin 6 lo PENALIZA, no lo favorece: apenas pasa su umbral empieza a
# ceder prioridad. Por eso:
#   - el speedtest va a tin 2 (umbral 100%, puede tomar todo el enlace)
#   - los rangos de puertos anchos de gaming son peligrosos: si un flujo
#     pesado cae por error en tin 5, se lo castiga. [R6-08] lo desasciende.
#
# ESCALERA QUE APLICA ESTE SCRIPT (de mayor a menor):
#   tin 6  EF 46   CONTROL-CRITICO   DNS, ICMP, SIP/RTP, Winbox
#   tin 5  CS2 16  GAMING            latencia critica, volumen bajo
#   tin 3  AF41 34 PRODUCTIVIDAD     Zoom, Meet, Teams, Classroom, correo
#   tin 3  AF31 26 MENSAJERIA        WhatsApp
#   tin 2  CS0 0   SPEEDTEST / WEB / REDES-SOCIALES / GENERAL
#   tin 1  AF11 10 STREAMING         YouTube, Netflix, Disney, HBO, Prime
#   tin 0  CS1 8   BULK              actualizaciones, tiendas de juegos
#                                    (ver [R6-06]: puede caer en tin 1)
#
# --- COMPROBACION DE TIN (para saber cual tabla tiene TU equipo) [R6-06] ----
# No hay contador por tin en RouterOS, asi que se mide por efecto:
#   1. Cliente de prueba, plan chico (10-20 M), sin otro trafico.
#   2. Arrancar una descarga grande desde un destino de la lista BULK-CDN
#      (por ejemplo una actualizacion de Steam o de Windows).
#   3. Con eso corriendo, correr un speedtest.
#      - Si el speedtest se lleva casi todo el plan y la descarga cede:
#        BULK esta en tin 0. La tabla vieja.
#      - Si se reparten mas o menos por igual: BULK esta compartiendo tin
#        con el resto y la separacion no existe. Tabla nueva.
#   En el segundo caso, la palanca real no es el DSCP sino bajar el peso del
#   bulk desde el borde (o aceptar que CAKE ya reparte por flujo).
# ============================================================================


# ============================================================================
# OVERHEAD: UNA SOLA FORMULA, DOS ESCUELAS   (igual que R5, sin cambios)
# ============================================================================
#   overhead = BASE + 4 por cada etiqueta VLAN + 8 si hay PPPoE
#
#   ESCUELA A = 18   cabecera Ethernet (14) + FCS (4)                mpu 64
#   ESCUELA B = 38   lo anterior + preambulo (7) + SFD (1) + IFG (12) mpu 84
#
# +------------------------------------------+----------+----------+
# | ESCENARIO                                | ESCUELA A| ESCUELA B|
# +------------------------------------------+----------+----------+
# | Ethernet / fibra directa, sin VLAN       |    18    |    38    |
# | IPoE o bridge con una VLAN               |    22    |    42    |
# | QinQ sin PPPoE                           |    26    |    46    |
# | PPPoE sin VLAN                           |    26    |    46    |
# | PPPoE + VLAN  (FTTH tipico en LATAM)     |    30    |    50    |
# | PPPoE + QinQ                             |    34    |    54    |
# +------------------------------------------+----------+----------+
#
# La escuela y el MPU tienen que ser LA MISMA: escuela A -> mpu 64,
# escuela B -> mpu 84. Mezclarlas es el error clasico:
#   A + mpu 84 -> un ACK de 40 B se contabiliza como 84: 45% de mas, y en un
#     plan con 5 M de subida son ~0.7 M de canal fantasma.
#   B + mpu 64 -> declaras que contas el medio fisico pero pones un piso que
#     lo ignora: subcontabilizas y el shaper se pasa de rate.
#
# SOBRE TUNELES (sumar al valor de la matriz)
#   GRE +24   EoIP +42   L2TP +40   L2TP/IPsec +70..90
#   WireGuard +60   OpenVPN UDP +54
#
# CAPA FISICA DISTINTA (no usar la matriz)
#   ADSL/VDSL con PPPoE -> cake-overhead-scheme=pppoe-ptm
#   Cablemodem DOCSIS   -> cake-overhead-scheme=docsis, mpu 64
#
# VALIDACION EMPIRICA (manda sobre cualquier tabla):
#   1. Ping en reposo al gateway     -> anotar promedio
#   2. Ping durante un speedtest     -> anotar bajo carga
#   3. Diferencia menor a 10 ms      = overhead correcto
#   4. Entre 10 y 30 ms              = aceptable
#   5. Mayor a 30 ms                 = sube 4 y repite
#
# ============================================================================
# COMPENSACION DE OVERHEAD EN EL PLAN  *** LEER SI "MIDE DE MENOS" ***
# ============================================================================
# Ookla reporta throughput de PAYLOAD TCP. CAKE conforma contando el frame
# completo a nivel L2. Con el shaper en el valor exacto del plan, la medicion
# SIEMPRE da por debajo, y no es un error de clasificacion.
#
#   overhead 18 -> ~3.5%      overhead 38 -> ~5.0%
#   overhead 42 -> ~5.3%      overhead 50 -> ~5.9%
#   mas ~1.6% de encabezados IP+TCP que Ookla tampoco cuenta.
#
#   rate-limit del plan = velocidad comercial x 1.07  (overhead 38-50)
#   rate-limit del plan = velocidad comercial x 1.05  (overhead 18-22)
#
#   Plan 100M con PPPoE+VLAN (oh 50):  rate-limit 107M/107M
#   Plan 300M con PPPoE+VLAN (oh 50):  rate-limit 321M/321M
#   Plan 50M  IPoE+VLAN     (oh 22):   rate-limit 52M/52M
#
# NO subir el overhead para "ganar" velocidad: el overhead mal declarado
# reintroduce bufferbloat en el equipo del cliente. Se compensa en el plan.
# ============================================================================


# ============================================================================
# SECCION 0 - VARIABLES Y GUARDAS
# ============================================================================
# *** AJUSTAR AQUI. UN SOLO LUGAR. ***

# Autodescubrimiento: "si" = el script explora el router, puebla las listas
# WAN y de clientes y CALCULA el overhead.
:global EVGAUTO "si"

# Escuela de overhead: "B" cuenta el medio fisico (preambulo+IFG), "A" solo
# cabeceras. De aqui salen el overhead base y el MPU.
:global EVGESCUELA "B"

# Overhead. Si EVGAUTO="si" este valor se RECALCULA solo.
:global EVGOH 50

# Interface-LIST del lado cliente.
#
# *** POR QUE UNA LISTA PROPIA Y NO "LAN" ***
# Es tentador reusar la lista LAN de EVG-FW2026 para que firewall y QoS vean
# lo mismo. NO lo hagas en el mismo cambio: si la LAN estaba vacia (caso
# tipico con PPPoE), al poblarla se ACTIVAN de golpe reglas del firewall que
# hoy cuentan cero (BCP38, modulo TVBOX, deteccion de conntrack). Unificar es
# una decision aparte, con su ventana y su verificacion.
:global EVGCLILIST "EVG-CLIENTES"

# Interface-list de uplinks
:global EVGWANIF "WAN"

# [R6-01] cake-nat. Acepta si / no / auto. "auto" mira si alguna cola agrupa
# una red y si hay src-nat de clientes.  *** NUNCA se pasa crudo a CAKE ***
:global EVGNAT "auto"

# [R6-05] cake-wash: "si" = CAKE elige el tin con el DSCP y despues lo pone en
# 0 al entregar. Recomendado. Ponlo en "no" SOLO si tenes clientes corporativos
# que hacen su propio QoS con el DSCP que les llega.
:global EVGWASH "si"

# Debe coincidir con $EVGWINBOX de EVG-FW2026
:global EVGWINBOXQ 8291

# Si es "si", el script pone interface-list=$EVGCLILIST en los ppp profiles que
# no tengan ninguna, para que las interfaces PPPoE dinamicas entren solas.
:global EVGPPPLIST "si"

# "normal" = diffserv8 + ack-filter + SNI en vivo + listas SNI completas
# "bajo"   = diffserv4, sin ack-filter, sin SNI en vivo, listas SNI reducidas
:global EVGCPU "normal"

# Inspeccion de SNI en vivo (reclasifica en el ClientHello). Se apaga sola si
# $EVGCPU="bajo".
:global EVGSNILIVE "si"

# Regla de flujo elefante. "no" = se crea DESHABILITADA (default).
:global EVGELEFANTE "no"
:global EVGELEBYTES 250000000

# [R6-08] Desascenso POR TASA de lo mal clasificado en tin 5 / tin 6.
# Una partida son decenas de kbps y una llamada RTP ~100 kbps; una descarga por
# el mismo puerto son megabits sostenidos. Se mide con connection-rate (ultimos
# segundos), asi que es REVERSIBLE: si el flujo baja, vuelve a su clase.
# Formato de RouterOS: 5M, 800k, 2M ...   "0" desactiva la regla.
:global EVGGAMERATE "5M"
:global EVGEFRATE "3M"

# [R6-06] DSCP de la clase BULK. 8 = CS1. Leer [R6-06] antes de cambiarlo.
:global EVGDSCPBULK 8

# [R6-16] Purga automatica de conexiones sin marca al terminar. "si" reclasifica
# de inmediato lo que ya estaba abierto; NO corta lo que ya tenia marca.
:global EVGPURGA "no"

# IPTV multicast (IGMP + 224.0.0.0/4). "si" solo si repartis IPTV multicast.
:global EVGIPTV "no"

# [R6-12] Borrar las entradas DINAMICAS aprendidas por SNI al reaplicar.
# Cuesta un ClientHello por destino y evita que queden IP clasificadas con el
# criterio de la version anterior.
:global EVGLIMPIALISTAS "si"

# RTT de referencia de CAKE. 100ms sirve para LATAM -> CDN en US/BR.
# Enlaces satelitales (Starlink): 200ms-300ms.
:global EVGRTT "100ms"

# [R6-02] Contador de bloques que fallaron al aplicarse.
:global EVGERR 0


# ============================================================================
# SECCION 0A - AUTODESCUBRIMIENTO DEL ROUTER
# ============================================================================
# Explora el equipo y deja listas las dos interface-list y el overhead.
#
# IDEMPOTENCIA: cada corrida borra SOLO los miembros que puso este script
# (comment con EVG-QOS2026-AUTO) y los vuelve a poner. Los miembros que
# agregaste a mano no se tocan NUNCA.
#
# QUE DETECTA Y COMO:
#   WAN  -> interfaz de cada ruta por defecto activa v4 y v6  [R6-03]
#           mas cada dhcp-client y cada pppoe-client habilitado
#   LAN  -> interfaz de cada dhcp-server habilitado (caso IPoE)
#           y, si hay PPPoE server, por /ppp profile interface-list
#   VLAN -> si la interfaz de cliente es una VLAN, si su padre tambien lo es
#           (QinQ), y si es un bridge con puertos VLAN
#
# LO QUE NO PUEDE ADIVINAR (revisar el log):
#   - clientes que entran por una interfaz fisica sin dhcp-server
#   - VLAN de gestion mezcladas con las de clientes
#   - un bridge que junta clientes y transito en el mismo dominio
#   - bridge con vlan-filtering y PVID por puerto (la etiqueta la pone el
#     bridge, no se ve en /interface vlan): verificar el overhead a mano

:global EVGnWan 0
:global EVGnLan 0
:global EVGvlanCli 0
:global EVGqinq 0
:global EVGhayPppoe 0
:global EVGhayDhcp 0

:if ($EVGAUTO = "si") do={

  :do {
    :if ([:len [/interface list find where name=$EVGWANIF]] = 0) do={
      /interface list add name=$EVGWANIF comment="EVG-QOS2026 | creada por autodescubrimiento"
    }
    :if ([:len [/interface list find where name=$EVGCLILIST]] = 0) do={
      /interface list add name=$EVGCLILIST comment="EVG-QOS2026 | creada por autodescubrimiento"
    }
  } on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudieron crear las interface-list." }

  /interface list member
  :foreach m in=[find where comment~"EVG-QOS2026-AUTO"] do={ :do { remove $m } on-error={} }

  # --- WAN por ruta por defecto activa (v4 y v6) --------------------------
  # [R6-03] immediate-gw puede ser:
  #     "192.168.1.1%ether1"                 -> gateway con interfaz
  #     "pppoe-out1"                         -> punto a punto, SIN "%"
  #     "1.1.1.1%ether1,2.2.2.2%ether2"      -> ECMP, varios separados por coma
  # R5 exigia "%" y no partia por comas: perdia el caso PPPoE-client y los dos
  # uplinks de un ECMP. Se agrega una coma al final para que el bucle cierre
  # siempre el ultimo elemento.
  :foreach r in=[/ip route find where dst-address="0.0.0.0/0"] do={
    :do {
      :if ([/ip route get $r active]) do={
        :local ig ([:tostr [/ip route get $r immediate-gw]] . ",")
        :local buf ""
        :local i 0
        :while ($i < [:len $ig]) do={
          :local ch [:pick $ig $i ($i + 1)]
          :if ($ch = ",") do={
            :if ([:len $buf] > 0) do={
              :local ifn $buf
              :local pos [:find $buf "%"]
              :if ([:typeof $pos] = "num") do={ :set ifn [:pick $buf ($pos + 1) [:len $buf]] }
              :if ([:len [/interface find where name=$ifn]] > 0) do={
                :if ([:len [find where list=$EVGWANIF and interface=$ifn]] = 0) do={
                  add list=$EVGWANIF interface=$ifn comment="EVG-QOS2026-AUTO | ruta por defecto v4"
                  :set EVGnWan ($EVGnWan + 1)
                }
              }
            }
            :set buf ""
          } else={ :set buf ($buf . $ch) }
          :set i ($i + 1)
        }
      }
    } on-error={}
  }
  :foreach r in=[/ipv6 route find where dst-address="::/0"] do={
    :do {
      :if ([/ipv6 route get $r active]) do={
        :local ig ([:tostr [/ipv6 route get $r immediate-gw]] . ",")
        :local buf ""
        :local i 0
        :while ($i < [:len $ig]) do={
          :local ch [:pick $ig $i ($i + 1)]
          :if ($ch = ",") do={
            :if ([:len $buf] > 0) do={
              :local ifn $buf
              :local pos [:find $buf "%"]
              :if ([:typeof $pos] = "num") do={ :set ifn [:pick $buf ($pos + 1) [:len $buf]] }
              :if ([:len [/interface find where name=$ifn]] > 0) do={
                :if ([:len [find where list=$EVGWANIF and interface=$ifn]] = 0) do={
                  add list=$EVGWANIF interface=$ifn comment="EVG-QOS2026-AUTO | ruta por defecto v6"
                  :set EVGnWan ($EVGnWan + 1)
                }
              }
            }
            :set buf ""
          } else={ :set buf ($buf . $ch) }
          :set i ($i + 1)
        }
      }
    } on-error={}
  }

  # --- WAN por dhcp-client y pppoe-client ----------------------------------
  :foreach c in=[/ip dhcp-client find where disabled=no] do={
    :do {
      :local ifn [:tostr [/ip dhcp-client get $c interface]]
      :if ([:len [find where list=$EVGWANIF and interface=$ifn]] = 0) do={
        add list=$EVGWANIF interface=$ifn comment="EVG-QOS2026-AUTO | dhcp-client"
        :set EVGnWan ($EVGnWan + 1)
      }
    } on-error={}
  }
  :foreach c in=[/interface pppoe-client find where disabled=no] do={
    :do {
      :local ifn [:tostr [/interface pppoe-client get $c name]]
      :if ([:len [find where list=$EVGWANIF and interface=$ifn]] = 0) do={
        add list=$EVGWANIF interface=$ifn comment="EVG-QOS2026-AUTO | pppoe-client"
        :set EVGnWan ($EVGnWan + 1)
      }
    } on-error={}
  }

  # --- LAN por dhcp-server (caso IPoE) -------------------------------------
  :foreach d in=[/ip dhcp-server find where disabled=no] do={
    :do {
      :set EVGhayDhcp 1
      :local ifn [:tostr [/ip dhcp-server get $d interface]]
      :if ([:len [find where list=$EVGWANIF and interface=$ifn]] > 0) do={
        :log warning ("EVG-QOS2026: la interfaz '" . $ifn . "' tiene dhcp-server PERO esta en la lista WAN. Se omite, revisala.")
      } else={
        :if ([:len [find where list=$EVGCLILIST and interface=$ifn]] = 0) do={
          add list=$EVGCLILIST interface=$ifn comment="EVG-QOS2026-AUTO | dhcp-server"
          :set EVGnLan ($EVGnLan + 1)
        }
      }
    } on-error={}
  }

  # --- PPPoE server presente ------------------------------------------------
  :if ([:len [/interface pppoe-server server find]] > 0) do={
    :set EVGhayPppoe 1
    # La interfaz fisica o VLAN donde escucha el PPPoE NO se agrega a la lista
    # de clientes: las reglas tienen que ver la interfaz pppoe-inX dinamica, no
    # el trunk. Eso lo resuelve /ppp profile interface-list.
    :foreach sv in=[/interface pppoe-server server find] do={
      :do {
        :local ifn [:tostr [/interface pppoe-server server get $sv interface]]
        :if ([:len [/interface vlan find where name=$ifn]] > 0) do={ :set EVGvlanCli 1 }
        # PPPoE escuchando sobre un bridge: mirar si los puertos son VLAN
        :if ([:len [/interface bridge find where name=$ifn]] > 0) do={
          :foreach bp in=[/interface bridge port find where bridge=$ifn] do={
            :do {
              :local pn [:tostr [/interface bridge port get $bp interface]]
              :if ([:len [/interface vlan find where name=$pn]] > 0) do={ :set EVGvlanCli 1 }
            } on-error={}
          }
        }
      } on-error={}
    }
  }

  # --- Encapsulacion de las interfaces de cliente ---------------------------
  :foreach m in=[find where list=$EVGCLILIST] do={
    :do {
      :local ifn [:tostr [get $m interface]]
      :local vid [/interface vlan find where name=$ifn]
      :if ([:len $vid] > 0) do={
        :set EVGvlanCli 1
        :local par [:tostr [/interface vlan get $vid interface]]
        :if ([:len [/interface vlan find where name=$par]] > 0) do={ :set EVGqinq 1 }
      }
      # bridge de clientes con puertos VLAN
      :if ([:len [/interface bridge find where name=$ifn]] > 0) do={
        :foreach bp in=[/interface bridge port find where bridge=$ifn] do={
          :do {
            :local pn [:tostr [/interface bridge port get $bp interface]]
            :if ([:len [/interface vlan find where name=$pn]] > 0) do={ :set EVGvlanCli 1 }
          } on-error={}
        }
      }
    } on-error={}
  }

  # --- Overhead calculado ---------------------------------------------------
  :local base 38
  :if ($EVGESCUELA = "A") do={ :set base 18 }
  :local calc $base
  :if ($EVGvlanCli = 1)  do={ :set calc ($calc + 4) }
  :if ($EVGqinq = 1)     do={ :set calc ($calc + 4) }
  :if ($EVGhayPppoe = 1) do={ :set calc ($calc + 8) }
  :if ($calc != $EVGOH) do={
    :log warning ("EVG-QOS2026: overhead recalculado de " . $EVGOH . " a " . $calc . " (escuela " . $EVGESCUELA . "). Si tenias uno validado con ping bajo carga, poner EVGAUTO=no y fijarlo.")
  }
  :set EVGOH $calc

  :log warning ("EVG-QOS2026 AUTODESCUBRIMIENTO: WAN=" . $EVGnWan . " LAN=" . $EVGnLan . " pppoe=" . $EVGhayPppoe . " dhcp=" . $EVGhayDhcp . " vlan=" . $EVGvlanCli . " qinq=" . $EVGqinq . " -> overhead=" . $EVGOH)

  :if ($EVGnLan = 0 and $EVGhayPppoe = 0) do={
    :log error "EVG-QOS2026: no se encontro NINGUNA interfaz de clientes (ni dhcp-server ni PPPoE server)."
    :log error "EVG-QOS2026: agregalas a mano: /interface list member add list=$EVGCLILIST interface=<iface>"
  }

  # --- Candidatas que no pudo clasificar ------------------------------------
  :foreach a in=[/ip address find where disabled=no] do={
    :do {
      :local net [/ip address get $a network]
      :local ifn [:tostr [/ip address get $a interface]]
      :local priv false
      :if ($net in 10.0.0.0/8)     do={ :set priv true }
      :if ($net in 172.16.0.0/12)  do={ :set priv true }
      :if ($net in 192.168.0.0/16) do={ :set priv true }
      :if ($net in 100.64.0.0/10)  do={ :set priv true }
      :if ($priv) do={
        :if ([:len [find where list=$EVGCLILIST and interface=$ifn]] = 0) do={
          :if ([:len [find where list=$EVGWANIF and interface=$ifn]] = 0) do={
            :log info ("EVG-QOS2026: candidata sin clasificar -> " . $ifn . " (" . $net . "). Si por ahi entran clientes, agregala a mano.")
          }
        }
      }
    } on-error={}
  }

} else={
  :log warning "EVG-QOS2026: autodescubrimiento APAGADO. Las listas y el overhead se usan tal como estan."
}


# ============================================================================
# SECCION 0B - GUARDAS
# ============================================================================
:global abortar false

# --- Guarda de version ------------------------------------------------------
:global rosver [/system resource get version]
:if ([:pick $rosver 0 1] != "7") do={
  :log error "EVG-QOS2026: este script requiere RouterOS 7.x. Version detectada: $rosver"
  :set abortar true
}

# --- [R6-09] CONNTRACK ------------------------------------------------------
# Todo el marcado es por connection-mark. Con conntrack en "no" no existen las
# conexiones: las ~45 reglas de mark-connection no matchean NUNCA y el QoS
# entero es decorativo. Es un caso real: hay ISP que lo apagan para ahorrar CPU
# en el borde.
:do {
  :local ct [:tostr [/ip firewall connection tracking get enabled]]
  :if ($ct = "no") do={
    :log error "EVG-QOS2026: CONNTRACK DESHABILITADO (/ip firewall connection tracking). Sin conntrack no hay connection-mark y este QoS no puede funcionar. Abortando."
    :set abortar true
  }
} on-error={ :log info "EVG-QOS2026: no se pudo leer el estado de conntrack." }

# --- [R6-09] BRIDGE SIN use-ip-firewall ------------------------------------
# Si dos clientes cuelgan del MISMO bridge, el trafico entre ellos se puentea
# en capa 2 y NO pasa por /ip firewall mangle: no se clasifica ni se conforma.
# Solo importa para trafico cliente-a-cliente dentro del bridge; lo que sale a
# internet se rutea y si pasa por mangle.
:if ([:len [/interface bridge find]] > 0) do={
  :do {
    :local uif [/interface bridge settings get use-ip-firewall]
    :if (!$uif) do={
      :log warning "EVG-QOS2026: hay bridge(s) y use-ip-firewall=no. El trafico PUENTEADO entre clientes del mismo bridge no pasa por mangle (no se clasifica). Para internet no cambia nada. Activar solo si de verdad necesitas clasificar trafico intra-bridge: cuesta CPU."
    }
  } on-error={}
}

# --- [R6-09] BYPASS-RAW de EVG-FW2026 activo -------------------------------
# El BYPASS de emergencia del firewall es un accept al principio de raw: corta
# el recorrido y las reglas de SNI de este QoS dejan de poblar las listas.
:do {
  :if ([:len [/ip firewall raw find where action="accept" and chain="prerouting" and disabled=no and comment~"BYPASS"]] > 0) do={
    :log error "EVG-QOS2026: el BYPASS-RAW de EVG-FW2026 esta HABILITADO. Mientras siga asi, las listas por SNI no se pueblan y la clasificacion se degrada a puertos."
  }
} on-error={}

# --- Guarda de la interface-list del lado cliente ---------------------------
:if ([:len [/interface list find where name=$EVGCLILIST]] = 0) do={
  /interface list add name=$EVGCLILIST comment="EVG-QOS2026 | Interfaces del lado cliente"
  :log warning "EVG-QOS2026: se creo la interface-list '$EVGCLILIST' (estaba vacia)."
}
:global nCli [:len [/interface list member find where list=$EVGCLILIST]]
:if ($nCli = 0) do={
  :log warning "EVG-QOS2026: la interface-list '$EVGCLILIST' esta VACIA."
  :log warning "EVG-QOS2026: si es PPPoE se va a poblar sola al levantar sesiones (ver EVGPPPLIST)."
  :log warning "EVG-QOS2026: si es IPoE/VLAN, agregalas AHORA: /interface list member add list=$EVGCLILIST interface=vlanXXX"
}

# --- Guarda de la interface-list WAN ---------------------------------------
:if ([:len [/interface list find where name=$EVGWANIF]] = 0) do={
  :log error "EVG-QOS2026: la interface-list '$EVGWANIF' NO EXISTE. Abortando."
  :set abortar true
} else={
  :if ([:len [/interface list member find where list=$EVGWANIF]] = 0) do={
    :log error "EVG-QOS2026: la interface-list '$EVGWANIF' esta VACIA. El wash entrante no va a contar."
    :set abortar true
  }
}

:if ($abortar) do={
  :log error "EVG-QOS2026: revisa /interface list y /interface list member."
  :error "EVG-QOS2026: guardas fallaron, no se aplico nada."
}

# --- Advertencia: fasttrack activo -----------------------------------------
:if ([:len [/ip firewall filter find where action="fasttrack-connection" and disabled=no]] > 0) do={
  :log error "EVG-QOS2026: HAY FASTTRACK ACTIVO. Saltea mangle y queues: el QoS NO funciona. Deshabilitalo."
}

# --- Advertencia: matchers limit= en forward/mangle ------------------------
# `limit` NO limita banda: limita cuantos PAQUETES hacen match con la regla.
# En trafico de datos produce cortes aleatorios y marcado parcial.
:do {
  :global lim [:len [/ip firewall filter find where chain="forward" and limit!="" and disabled=no]]
  :if ($lim > 0) do={
    :log error "EVG-QOS2026: hay $lim regla(s) de FORWARD con matcher limit=. Corta por pps, no por banda. Revisalas."
  }
} on-error={ :log info "EVG-QOS2026: no se pudo evaluar matchers limit= en filter" }
:do {
  :global limm [:len [/ip firewall mangle find where limit!="" and disabled=no]]
  :if ($limm > 0) do={
    :log error "EVG-QOS2026: hay $limm regla(s) de MANGLE con matcher limit=. El marcado va a ser parcial y el QoS erratico."
  }
} on-error={ :log info "EVG-QOS2026: no se pudo evaluar matchers limit= en mangle" }

# --- Aviso de balanceo PCC --------------------------------------------------
# Con balanceo por PCC el marcado de ruteo y el de QoS se pisan: las conexiones
# cambian de tabla y la clasificacion queda a medias. Antes de insistir con QoS
# aca, el esquema tiene que pasar a PBR.
:do {
  :global EVGpcc [:len [/ip firewall mangle find where per-connection-classifier!="" and disabled=no]]
  :if ($EVGpcc > 0) do={
    :log error ("EVG-QOS2026: hay " . $EVGpcc . " regla(s) de balanceo PCC. El QoS y el marcado de ruteo se pisan. Pasar el esquema a PBR antes de confiar en esta clasificacion.")
  }
} on-error={}

# --- [R6-10] IPv6 CLASIFICADO PERO NO CONFORMADO ---------------------------
# La cola simple dinamica de PPP tiene como target la IP v4 del cliente. El
# trafico IPv6 de ese mismo cliente NO entra a esa cola: se clasifica (todo el
# espejo IPv6 de la SECCION 10) y despues sale SIN SHAPING.
# Esto no es un detalle: con IPv6 activo y sin cola, el cliente NO tiene plan
# por IPv6, y ademas el QoS pierde el control del bufferbloat justo en el
# trafico que mas crece (YouTube y Netflix ya son mayoritariamente v6).
:global EVGv6 0
:global EVGq6 0
:do { :if ([:len [/ipv6 address find where disabled=no and !link-local]] > 0) do={ :set EVGv6 1 } } on-error={}
:do { :if ([:len [/ipv6 dhcp-server find]] > 0) do={ :set EVGv6 1 } } on-error={}
:do { :if ([:len [/ipv6 pool find]] > 0) do={ :set EVGv6 1 } } on-error={}
:do {
  :foreach q in=[/queue simple find] do={
    :do { :if ([:tostr [get $q target]]~":") do={ :set EVGq6 1 } } on-error={}
  }
} on-error={}
:if ($EVGv6 = 1 and $EVGq6 = 0) do={
  :log error "EVG-QOS2026: HAY IPv6 EN ESTE ROUTER Y NINGUNA COLA SIMPLE TIENE TARGET IPv6."
  :log error "EVG-QOS2026: el trafico IPv6 de los clientes se clasifica pero NO se conforma (sale sin plan). Ver la nota IPv6 al final del archivo."
}

# --- MPU: SE DERIVA DE LA ESCUELA, NO SE TOCA A MANO -----------------------
# El MPU es el PISO de contabilizacion: CAKE cuenta cada paquete como
#   max(tamaño_real + overhead, mpu)
# No limita el enlace. Solo muerde en paquetes chicos (ACK, VoIP, DNS, gaming);
# con un paquete de 1500 bytes nunca se activa.
#   ESCUELA A (overhead 18/22/26/30) -> mpu 64
#   ESCUELA B (overhead 38/42/46/50) -> mpu 84
# Casos por capa fisica (fijar a mano si aplica): DOCSIS 64; ATM/ADSL usar
# cake-overhead-scheme, que redondea a celdas.
:global EVGMPU 84
:if ($EVGESCUELA = "A") do={ :set EVGMPU 64 }

# --- [R6-01] TRADUCCION DE cake-nat ----------------------------------------
# RouterOS espera yes/no. El script se maneja en si/no/auto y traduce aca; el
# valor crudo NUNCA llega a CAKE.
:global EVGNATQ "no"
:if ($EVGNAT = "si"  or $EVGNAT = "yes") do={ :set EVGNATQ "yes" }
:if ($EVGNAT = "auto") do={
  :local agrupa 0
  :do {
    :foreach q in=[/queue simple find where !dynamic] do={
      :do {
        :local tg [:tostr [get $q target]]
        :if (($tg~"/") and (!($tg~"/32")) and (!($tg~"/128"))) do={ :set agrupa ($agrupa + 1) }
      } on-error={}
    }
  } on-error={}
  :local haynat 0
  :do {
    :if ([:len [/ip firewall nat find where action~"masquerade|src-nat" and chain="srcnat" and disabled=no]] > 0) do={ :set haynat 1 }
  } on-error={}
  :if ($agrupa > 0 and $haynat = 1) do={
    :set EVGNATQ "yes"
    :log warning ("EVG-QOS2026: cake-nat=yes AUTO -> " . $agrupa . " cola(s) agrupan una red y hay src-nat. CAKE va a mirar la IP interna para repartir.")
  } else={
    :log info ("EVG-QOS2026: cake-nat=no AUTO (colas que agrupan red=" . $agrupa . ", src-nat=" . $haynat . ")")
  }
}

# --- Ajustes derivados del modo CPU ----------------------------------------
# [R6-17] El ahorro real de "bajo" NO esta en diffserv4 (elegir el tin es una
# lectura de tabla, no cuesta): esta en no evaluar reglas por paquete. Por eso
# en modo bajo se apaga el SNI en vivo y se recortan las listas SNI largas.
:global EVGDIFF "diffserv8"
:global EVGACK "filter"
:global EVGSNIFULL "si"
:if ($EVGCPU = "bajo") do={
  :set EVGDIFF "diffserv4"
  :set EVGACK "none"
  :set EVGSNILIVE "no"
  :set EVGSNIFULL "no"
  :log warning "EVG-QOS2026: MODO CPU BAJO -> diffserv4, sin ack-filter, sin SNI en vivo, listas SNI reducidas."
  :log warning "EVG-QOS2026: en diffserv4 el mapeo colapsa: EF/CS5->Voice, AF4x/CS3->Video, resto->Best Effort. STREAMING y BULK pueden terminar en la misma clase que la web."
}

# --- cake-wash --------------------------------------------------------------
:global EVGWASHQ "yes"
:if ($EVGWASH = "no") do={ :set EVGWASHQ "no" }

:log warning "EVG-QOS2026-R6: INICIO (oh=$EVGOH mpu=$EVGMPU lista=$EVGCLILIST cpu=$EVGCPU diffserv=$EVGDIFF nat=$EVGNATQ wash=$EVGWASHQ snilive=$EVGSNILIVE elefante=$EVGELEFANTE)"


# ============================================================================
# SECCION 1 - LIMPIEZA IDEMPOTENTE (solo tag EVG-QOS2026)
# ============================================================================
# Borra R2..R5 y la corrida anterior de R6. Las reglas de cadena propia
# (EVG-SNI, EVG-MARK, EVG-SNILIVE) tambien llevan el tag, asi que caen aca y la
# cadena desaparece sola cuando se queda sin reglas.
:do { :foreach r in=[/ip firewall mangle   find where comment~"EVG-QOS2026"] do={ /ip firewall mangle   remove $r } } on-error={ :set EVGERR ($EVGERR + 1) }
:do { :foreach r in=[/ip firewall raw      find where comment~"EVG-QOS2026"] do={ /ip firewall raw      remove $r } } on-error={ :set EVGERR ($EVGERR + 1) }
:do { :foreach r in=[/ipv6 firewall mangle find where comment~"EVG-QOS2026"] do={ /ipv6 firewall mangle remove $r } } on-error={ :set EVGERR ($EVGERR + 1) }
:do { :foreach r in=[/ipv6 firewall raw    find where comment~"EVG-QOS2026"] do={ /ipv6 firewall raw    remove $r } } on-error={ :set EVGERR ($EVGERR + 1) }

# OJO: NO borra SPEEDTEST-LOCAL cargada a mano (no lleva el tag).
:do { :foreach r in=[/ip firewall address-list find where comment~"EVG-QOS2026"] do={ :do { /ip firewall address-list remove $r } on-error={} } } on-error={ :set EVGERR ($EVGERR + 1) }
# [R6-12] R5 no tocaba las listas IPv6.
:do { :foreach r in=[/ipv6 firewall address-list find where comment~"EVG-QOS2026"] do={ :do { /ipv6 firewall address-list remove $r } on-error={} } } on-error={}

# --- [R6-12] Entradas DINAMICAS aprendidas por SNI --------------------------
# Las que crea add-dst-to-address-list NO llevan comentario, asi que el borrado
# por tag no las ve: al cambiar de version quedaban IP clasificando con el
# criterio viejo hasta 12 h. Se incluyen los nombres CON ESPACIO de R5 para que
# la migracion a los nombres nuevos [R6-13] no deje huerfanas.
:if ($EVGLIMPIALISTAS = "si") do={
  :foreach l in={"YOUTUBE";"NETFLIX";"HBO-MAX";"AMAZON-VIDEO";"DISNEY-PLUS";"DIRECTGO";"WA-WEB";"FACEBOOK";"INSTAGRAM";"TIKTOK";"TWITTER";"MEET-GOOGLE";"HANGOUTS-GOOGLE";"CLASSROOM";"ZOOM";"BULK-CDN";"SPEEDTEST-SERVERS";"HBO MAX";"AMAZON VIDEO";"DISNEY PLUS";"WEB WHATSAPP";"MEET GOOGLE";"HANGOUTS GOOGLE"} do={
    :do { :foreach e in=[/ip firewall address-list find where list=$l and dynamic=yes] do={ :do { /ip firewall address-list remove $e } on-error={} } } on-error={}
  }
  :foreach l in={"YOUTUBE-V6";"STREAMING-V6";"SOCIAL-V6";"PRODUCTIVIDAD-V6";"WHATSAPP-V6";"BULK-V6";"SPEEDTEST-V6"} do={
    :do { :foreach e in=[/ipv6 firewall address-list find where list=$l and dynamic=yes] do={ :do { /ipv6 firewall address-list remove $e } on-error={} } } on-error={}
  }
}

:foreach n in={"EVG-QOS-REPORT";"EVG-QOS-COLAS"} do={
  :do { /system scheduler remove [/system scheduler find where name=$n] } on-error={}
  :do { /system script    remove [/system script    find where name=$n] } on-error={}
}


# ============================================================================
# SECCION 2 - QUEUE TYPE CAKE
# ============================================================================
# cake-flowmode=triple-isolate: fairness por host Y por flujo dentro de la
#   cola. Es lo que hace innecesaria la regla de elefante.
# cake-mpu: piso de contabilizacion. Sin esto los paquetes chicos (ACK, DNS,
#   VoIP) se cuentan de menos y el shaper se pasa de rate.
# cake-wash=$EVGWASHQ [R6-05]: CAKE elige el tin con el DSCP y DESPUES lo pone
#   en 0 al entregar. Asi el CPE del cliente no mapea nuestro AF11/CS1 a
#   AC_BK de WiFi, y no le exportamos DSCP al upstream.
# find name="EVG-CAKE2026" CON COMILLAS: sin ellas RouterOS evalua el nombre
#   como expresion (lee los guiones como resta), el find sale vacio aunque el
#   objeto exista, y el add falla con "name already used".
/queue type
:do {
  :if ([:len [find where name="EVG-CAKE2026"]] = 0) do={
    add name=EVG-CAKE2026 kind=cake \
        cake-diffserv=$EVGDIFF \
        cake-ack-filter=$EVGACK \
        cake-overhead=$EVGOH \
        cake-mpu=$EVGMPU \
        cake-nat=$EVGNATQ \
        cake-wash=$EVGWASHQ \
        cake-rtt=$EVGRTT \
        cake-flowmode=triple-isolate
  } else={
    set [find where name="EVG-CAKE2026"] kind=cake \
        cake-diffserv=$EVGDIFF \
        cake-ack-filter=$EVGACK \
        cake-overhead=$EVGOH \
        cake-mpu=$EVGMPU \
        cake-nat=$EVGNATQ \
        cake-wash=$EVGWASHQ \
        cake-rtt=$EVGRTT \
        cake-flowmode=triple-isolate
  }
} on-error={
  :set EVGERR ($EVGERR + 1)
  :log error "EVG-QOS2026: NO se pudo crear/actualizar el queue type EVG-CAKE2026. Sin el, las colas quedan con su tipo anterior. Revisar que este build soporte kind=cake y todas las propiedades cake-*."
}


# ============================================================================
# SECCION 3 - PPP PROFILE  (queue-type + interface-list)
# ============================================================================
# Toda esta seccion se salta si el equipo NO tiene PPPoE server: en un borde
# IPoE los perfiles PPP no atienden a nadie y tocarlos solo ensucia.
:if ($EVGhayPppoe = 0) do={
  :log warning "EVG-QOS2026: sin PPPoE server en este equipo -> se omiten los perfiles PPP. Los clientes se conforman por colas simples."
} else={

# [R6-14] El formato "tipo/tipo" es el de /queue simple. En /ppp profile el
# queue-type puede esperar un solo nombre segun build: se intenta simple y solo
# si falla se prueba el par.
/ppp profile
:global qtOK 0
:global qtNO 0
:foreach i in=[find where rate-limit!=""] do={
  :do { set $i queue-type="EVG-CAKE2026"; :set qtOK ($qtOK + 1) } on-error={
    :do { set $i queue-type="EVG-CAKE2026/EVG-CAKE2026"; :set qtOK ($qtOK + 1) } on-error={
      :set qtNO ($qtNO + 1)
      :log warning ("EVG-QOS2026: no se pudo fijar queue-type en profile " . [get $i name])
    }
  }
}
:log warning "EVG-QOS2026: ppp profile con queue-type CAKE -> $qtOK ok, $qtNO fallaron."

# --- Poblado automatico de la interface-list del lado cliente ---------------
# /ppp profile tiene la propiedad `interface-list`: las interfaces PPPoE
# dinamicas se agregan solas a esa lista al autenticar. Es la unica forma
# limpia de tener PPPoE dentro de un in-interface-list.
:global pplSet 0
:global pplOtra 0
:if ($EVGPPPLIST = "si") do={
  :foreach i in=[find] do={
    :do {
      :local il [:tostr [get $i interface-list]]
      :local nm [get $i name]
      :if ([:len $il] = 0 or $il = "none") do={
        set $i interface-list=$EVGCLILIST
        :set pplSet ($pplSet + 1)
      } else={
        :if ($il != $EVGCLILIST) do={
          :log warning ("EVG-QOS2026: profile '" . $nm . "' ya usa interface-list='" . $il . "' (no se toco). Si esa no es la lista del QoS, las reglas no lo van a ver.")
          :set pplOtra ($pplOtra + 1)
        }
      }
    } on-error={ :log info "EVG-QOS2026: este RouterOS no expone /ppp profile interface-list; poblar la lista a mano." }
  }
  :log warning "EVG-QOS2026: ppp profiles con interface-list=$EVGCLILIST -> $pplSet nuevos, $pplOtra con otra lista."
}

# --- Guardas de plan --------------------------------------------------------
:global sinrl [:len [/ppp profile find where rate-limit=""]]
:if ($sinrl > 0) do={
  :log error "EVG-QOS2026: $sinrl ppp profile(s) SIN rate-limit -> esos clientes NO tienen cola, es decir NO tienen CAKE ni QoS."
  :foreach p in=[/ppp profile find where rate-limit=""] do={
    :log warning ("EVG-QOS2026: profile sin rate-limit -> " . [/ppp profile get $p name])
  }
}
# Referencias huerfanas de queue-type (ej. queue-type=*12)
:foreach p in=[/ppp profile find] do={
  :do {
    :local qt [:tostr [/ppp profile get $p queue-type]]
    :if ($qt~"^\\*") do={
      :log error ("EVG-QOS2026: profile '" . [/ppp profile get $p name] . "' tiene queue-type HUERFANO '" . $qt . "'. Corregir a EVG-CAKE2026.")
    }
  } on-error={}
}

}


# ============================================================================
# SECCION 4 - QUEUE SIMPLE  (respeta colas propias)
# ============================================================================
# Solo se tocan las colas que estan en un queue-type por defecto. Las colas
# hechas a proposito (priorizacion por plan, colas de evento, colas padre)
# conservan el suyo y se reportan.
/queue simple
:global tocadas 0
:global saltadas 0
:global agrupa 0
:global sinlim 0
:foreach q in=[find where !dynamic] do={
  :do {
    :local qt [:tostr [get $q queue]]
    :if ($qt~"^default" or $qt~"^pcq" or $qt~"^ethernet-default" or $qt~"^wireless-default" or $qt~"^synchronous-default" or $qt~"^hotspot-default") do={
      :do { set $q queue="EVG-CAKE2026/EVG-CAKE2026"; :set tocadas ($tocadas + 1) } on-error={}
    } else={
      :if (!($qt~"EVG-CAKE2026")) do={
        :log info ("EVG-QOS2026: cola '" . [get $q name] . "' conserva su queue-type '" . $qt . "' (no se toco)")
        :set saltadas ($saltadas + 1)
      }
    }
    # Cola cuyo target es una RED y no un host: con cake-nat=no y
    # triple-isolate, varios clientes dentro de esa cola compiten como uno.
    :local tg [:tostr [get $q target]]
    :if (($tg~"/") and (!($tg~"/32")) and (!($tg~"/128"))) do={ :set agrupa ($agrupa + 1) }
    # [R6-15] Cola sin max-limit: no conforma nada, y CAKE sin rate no sirve.
    :local ml [:tostr [get $q max-limit]]
    :if ($ml = "" or $ml = "0/0") do={
      :set sinlim ($sinlim + 1)
      :log warning ("EVG-QOS2026: cola '" . [get $q name] . "' SIN max-limit -> no conforma; CAKE ahi no hace nada.")
    }
  } on-error={}
}
:log warning "EVG-QOS2026: queue simple -> CAKE en $tocadas, respetadas $saltadas con queue-type propio, $sinlim sin max-limit."
:if ($agrupa > 0) do={
  :log warning "EVG-QOS2026: $agrupa cola(s) simple(s) apuntan a una RED y no a un host. Ahi conviene cake-nat=yes (EVGNAT) o flowmode=dual-dsthost."
}


# ============================================================================
# SECCION 5 - ADDRESS-LIST ESTATICAS
# ============================================================================
# [R6-13] Nombres sin espacios. Los de R5 con espacio ("HBO MAX", "WEB
# WHATSAPP", ...) quedaron en la limpieza de la SECCION 1.
/ip firewall address-list
:do {
  :foreach d in={"outlook.office.com";"outlook.office365.com";"smtp.office365.com";"r1.res.office365.com";"lync.com";"teams.microsoft.com";"broadcast.skype.com";"skypeforbusiness.com";"online.office.com";"excel.office.live.com";"onenote.office.live.com";"office.live.com";"cdn.office.net"} do={
    :if ([:len [find where address=$d and list=OFFICE365]] = 0) do={
      add address=$d list=OFFICE365 comment="EVG-QOS2026 | Office365"
    }
  }
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: fallo la carga de OFFICE365 (resolucion DNS?)." }

# --- SPEEDTEST-LOCAL: servidor Ookla on-net --------------------------------
# *** LISTA MANUAL POR CLIENTE. ES LA QUE RESUELVE EL CASO ON-NET. ***
# Los servidores Ookla que monta el ISP o el upstream NO tienen dominio
# *.ookla.com ni *.speedtest.net, asi que ningun matching por SNI los encuentra.
# Y ademas ese trafico NO sale por la WAN: es on-net.
# Agregar SIN el tag EVG-QOS2026 (si no, se borra al reaplicar):
#   /ip firewall address-list add list=SPEEDTEST-LOCAL address=1.2.3.4 comment="ookla on-net"
# Para descubrir la IP: mirar SPEEDTEST-LOCAL-AUTO despues de correr un test.
#
# Se crea con un placeholder deshabilitado para que la lista exista y el
# reporte pueda contarla (mismo patron que EVG-FW2026 [FIX-34]).
:do {
  :if ([:len [find where list=SPEEDTEST-LOCAL]] = 0) do={
    add list=SPEEDTEST-LOCAL address=127.0.0.1 disabled=yes comment="EVG-QOS2026 | placeholder: reemplazar por la IP real del servidor on-net"
  }
} on-error={}


# ============================================================================
# SECCION 6 - RAW IPv4: poblacion de listas por SNI (TCP/443)
# ============================================================================
# [R6-07] TODO va en la cadena propia EVG-SNI, con UNA sola regla de entrada.
# En R5 estas ~60 reglas se evaluaban contra CADA paquete que pasaba por raw
# (443 o no). Ahora un paquete que no es 443/80 de cliente ve una sola regla.
#
# raw prerouting sigue siendo el lugar mas barato para leer el SNI. Estas listas
# sirven para la SEGUNDA conexion en adelante; la primera la resuelve el bloque
# de SNI en vivo (9.1).
/ip firewall raw
:do {
  add action=jump chain=prerouting jump-target=EVG-SNI protocol=tcp dst-port=443,80 in-interface-list=$EVGCLILIST comment="EVG-QOS2026 | GATE -> cadena EVG-SNI (una sola evaluacion para lo que no es web)"
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudo crear el GATE de raw. Sin el, la cadena EVG-SNI no se recorre y las listas por SNI quedan vacias." }

# --- YOUTUBE ---------------------------------------------------------------
:do { :foreach h in={"*youtube.com*";"*.youtube.com";"*googlevideo.com*";"*ytimg.com*"} do={
  add action=add-dst-to-address-list address-list=YOUTUBE address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI YOUTUBE" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: fallo el bloque SNI YOUTUBE." }
# --- NETFLIX ---------------------------------------------------------------
:do { :foreach h in={"*netflix*";"*nflxvideo*";"*nflxso*"} do={
  add action=add-dst-to-address-list address-list=NETFLIX address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI NETFLIX" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
# --- HBO MAX ---------------------------------------------------------------
:do { :foreach h in={"*.max.com";"*.hbogo.com";"*.hbomaxcdn.com";"*.hbo.map.fastly.net"} do={
  add action=add-dst-to-address-list address-list=HBO-MAX address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI HBO" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
# --- AMAZON VIDEO ----------------------------------------------------------
:do { :foreach h in={"*primevideo*";"*.pv-cdn.net";"*.amazonvideo.com";"*.media-amazon.com";"*.aiv-cdn.net"} do={
  add action=add-dst-to-address-list address-list=AMAZON-VIDEO address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI PRIME" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
# --- DISNEY PLUS -----------------------------------------------------------
:do { :foreach h in={"*.disneyplus.com";"*.disney-plus.net";"*.starott.com";"*.cdn.registerdisney.go.com";"*.disneyplus.bn5x.net";"*.bamgrid.com"} do={
  add action=add-dst-to-address-list address-list=DISNEY-PLUS address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI DISNEY" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
# --- DIRECTV GO ------------------------------------------------------------
:do { :foreach h in={"*.directvgo.com";"*.dtvott.com";"*.dtvott-cbc.akamaized.net";"*.directv.com"} do={
  add action=add-dst-to-address-list address-list=DIRECTGO address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI DIRECTV" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
# --- WHATSAPP --------------------------------------------------------------
:do { :foreach h in={"*.web.whatsapp.com";"*.graph.whatsapp.net";"*.whatsapp.com";"*.static.whatsapp.net";"*.scontent.whatsapp.net";"*.whatsapp.net"} do={
  add action=add-dst-to-address-list address-list=WA-WEB address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI WHATSAPP" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
# --- MEET / HANGOUTS / CLASSROOM / ZOOM ------------------------------------
:do { :foreach h in={"*.meet.google.com";"*.stream.meet.google.com"} do={
  add action=add-dst-to-address-list address-list=MEET-GOOGLE address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI MEET" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
:do { :foreach h in={"*.hangouts.google.com";"*.hangouts.googleapis.com";"*.chat.google.com"} do={
  add action=add-dst-to-address-list address-list=HANGOUTS-GOOGLE address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI HANGOUTS" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
:do { :foreach h in={"*.classroom.google.com";"*.gclassroom.googleapis.com"} do={
  add action=add-dst-to-address-list address-list=CLASSROOM address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI CLASSROOM" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
:do { :foreach h in={"*.zoom.us";"*.zoom.com.cn";"*.cloudfront.zoom.us";"*.zoomcloudstatic.com"} do={
  add action=add-dst-to-address-list address-list=ZOOM address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI ZOOM" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }

# --- Redes sociales y BULK: solo en modo CPU normal  [R6-17] ---------------
# Son las dos listas mas largas y las que menos cambian la experiencia: las
# sociales van al mismo tin que la web (CS0) y el bulk, si no se detecta por
# SNI, cae en NAVEGACION-WEB, que tampoco lo prioriza.
:if ($EVGSNIFULL = "si") do={
  :do { :foreach h in={"*.fbcdn.net";"*.msngr.com";"*.facebook.net";"*.messenger.com";"*.facebook.com";"*fbcdn*"} do={
    add action=add-dst-to-address-list address-list=FACEBOOK address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI FACEBOOK" tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  :do { :foreach h in={"*.cdninstagram.com";"*.instagram.com";"*.i.instagram.com";"*.scontent.cdninstagram.com";"*.instagr.am"} do={
    add action=add-dst-to-address-list address-list=INSTAGRAM address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI INSTAGRAM" tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  :do { :foreach h in={"*.tiktok.com";"*.tiktokcdn-us.com";"*.tiktokv.com";"*.tiktokcdn.com";"*.byteoversea.com";"*.ibytedtos.com"} do={
    add action=add-dst-to-address-list address-list=TIKTOK address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI TIKTOK" tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  :do { :foreach h in={"*.api.twitter.com";"*.twimg.com";"*.t.co";"*.x.com"} do={
    add action=add-dst-to-address-list address-list=TWITTER address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI TWITTER" tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  :do { :foreach h in={"*.windowsupdate.com";"*.delivery.mp.microsoft.com";"*.dl.delivery.mp.microsoft.com";"*.update.microsoft.com";"*.steamcontent.com";"*.steamcdn-a.akamaihd.net";"*.cm.steampowered.com";"*.gs2.ww.prod.dl.playstation.net";"*.playstation.net";"*.xboxlive.com";"*.assets1.xboxlive.com";"*.mesu.apple.com";"*.swcdn.apple.com";"*.appldnld.apple.com";"*.dl.google.com";"*.android.clients.google.com";"*.hac.lp1.d4c.nintendo.net";"*.nintendo.net";"*.epicgames.com";"*.download.epicgames.com"} do={
    add action=add-dst-to-address-list address-list=BULK-CDN address-list-timeout=12h chain=EVG-SNI comment="EVG-QOS2026 | SNI BULK" tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
} else={
  :log warning "EVG-QOS2026: CPU bajo -> no se cargan las listas SNI de redes sociales ni BULK."
}


# ============================================================================
# SECCION 7 - RAW IPv4: SPEEDTEST
# ============================================================================
# NO incluye fast.com: comparte infra con Netflix (Open Connect), listarlo
# arrastraria todo Netflix a la clase de speedtest.
:do { :foreach h in={"*.ookla.com";"*.speedtest.net";"*.speedtestcustom.com";"*.nperf.com";"*.nperf.net";"*.measurement-lab.org";"*.measurementlab.net";"*.measurementlab.googleusercontent.com";"*.librespeed.org";"*.speedof.me";"*.testmy.net";"*.openspeedtest.com"} do={
  add action=add-dst-to-address-list address-list=SPEEDTEST-SERVERS address-list-timeout=2h chain=EVG-SNI comment="EVG-QOS2026-ST | SNI SPEEDTEST" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }
:do { :foreach h in={"speed.cloudflare.com";"*.waveform.com"} do={
  add action=add-dst-to-address-list address-list=SPEEDTEST-SERVERS address-list-timeout=30m chain=EVG-SNI comment="EVG-QOS2026-ST | SNI SPEEDTEST CF" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1) }

# --- Descubrimiento del servidor Ookla on-net ------------------------------
# Solo REGISTRA (no clasifica): despues de que un cliente corra un test, aca
# aparece la IP del servidor que uso. De ahi se copia a SPEEDTEST-LOCAL.
#   /ip firewall address-list print where list=SPEEDTEST-LOCAL-AUTO
# Va en prerouting (no es 443) y solo mira el SYN: un paquete por conexion.
:do {
  add action=add-dst-to-address-list address-list=SPEEDTEST-LOCAL-AUTO address-list-timeout=7d chain=prerouting comment="EVG-QOS2026-ST | AUTO descubre servidor 8080" dst-port=8080 in-interface-list=$EVGCLILIST protocol=tcp tcp-flags=syn,!ack
} on-error={ :set EVGERR ($EVGERR + 1) }


# ============================================================================
# SECCION 8 - RAW IPv6: mismas listas por SNI
# ============================================================================
/ipv6 firewall raw
:do {
  add action=jump chain=prerouting jump-target=EVG-SNI-V6 protocol=tcp dst-port=443,80 in-interface-list=$EVGCLILIST comment="EVG-QOS2026 | GATE V6 -> cadena EVG-SNI-V6"
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudo crear el GATE de raw IPv6." }

:do { :foreach h in={"*youtube.com*";"*.youtube.com";"*googlevideo.com*";"*ytimg.com*"} do={
  add action=add-dst-to-address-list address-list=YOUTUBE-V6 address-list-timeout=12h chain=EVG-SNI-V6 comment="EVG-QOS2026 | SNI V6 YOUTUBE" tls-host=$h
} } on-error={ :set EVGERR ($EVGERR + 1); :log warning "EVG-QOS2026: este build no acepta tls-host en /ipv6 firewall raw; la clasificacion IPv6 por SNI queda apagada." }
:do { :foreach h in={"*netflix*";"*nflxvideo*";"*nflxso*";"*.disneyplus.com";"*.disney-plus.net";"*.bamgrid.com";"*primevideo*";"*.amazonvideo.com";"*.aiv-cdn.net";"*.max.com";"*.hbomaxcdn.com"} do={
  add action=add-dst-to-address-list address-list=STREAMING-V6 address-list-timeout=12h chain=EVG-SNI-V6 comment="EVG-QOS2026 | SNI V6 STREAMING" tls-host=$h
} } on-error={}
:do { :foreach h in={"*.zoom.us";"*.meet.google.com";"*.stream.meet.google.com";"*.chat.google.com";"*.classroom.google.com";"teams.microsoft.com";"*.cdn.office.net"} do={
  add action=add-dst-to-address-list address-list=PRODUCTIVIDAD-V6 address-list-timeout=12h chain=EVG-SNI-V6 comment="EVG-QOS2026 | SNI V6 PROD" tls-host=$h
} } on-error={}
:do { :foreach h in={"*.whatsapp.com";"*.whatsapp.net";"*.graph.whatsapp.net";"*.scontent.whatsapp.net"} do={
  add action=add-dst-to-address-list address-list=WHATSAPP-V6 address-list-timeout=12h chain=EVG-SNI-V6 comment="EVG-QOS2026 | SNI V6 WA" tls-host=$h
} } on-error={}
:do { :foreach h in={"*.ookla.com";"*.speedtest.net";"*.speedtestcustom.com";"*.nperf.com";"*.measurementlab.net";"*.librespeed.org";"speed.cloudflare.com"} do={
  add action=add-dst-to-address-list address-list=SPEEDTEST-V6 address-list-timeout=2h chain=EVG-SNI-V6 comment="EVG-QOS2026-ST | SNI V6 SPEEDTEST" tls-host=$h
} } on-error={}
:if ($EVGSNIFULL = "si") do={
  :do { :foreach h in={"*.fbcdn.net";"*.facebook.com";"*.messenger.com";"*.cdninstagram.com";"*.instagram.com";"*.tiktok.com";"*.tiktokcdn.com";"*.tiktokv.com";"*.twimg.com";"*.x.com"} do={
    add action=add-dst-to-address-list address-list=SOCIAL-V6 address-list-timeout=12h chain=EVG-SNI-V6 comment="EVG-QOS2026 | SNI V6 SOCIAL" tls-host=$h
  } } on-error={}
  :do { :foreach h in={"*.windowsupdate.com";"*.delivery.mp.microsoft.com";"*.dl.delivery.mp.microsoft.com";"*.steamcontent.com";"*.playstation.net";"*.xboxlive.com";"*.mesu.apple.com";"*.swcdn.apple.com";"*.dl.google.com";"*.nintendo.net";"*.epicgames.com"} do={
    add action=add-dst-to-address-list address-list=BULK-V6 address-list-timeout=12h chain=EVG-SNI-V6 comment="EVG-QOS2026 | SNI V6 BULK" tls-host=$h
  } } on-error={}
}


# ============================================================================
# SECCION 9 - MANGLE IPv4
# ============================================================================
/ip firewall mangle

# --- 9.0 WASH DE DSCP (DE INGRESO) -----------------------------------------
# Se borra el DSCP que viene de afuera y el que pone el equipo del cliente.
# Sin esto, cualquiera marca EF y se cuela en tin 6.
# OJO: esto es el lavado de ENTRADA. El de SALIDA lo hace CAKE (cake-wash,
# [R6-05]) DESPUES de elegir el tin. NO agregar un change-dscp en postrouting
# para "no exportar DSCP": el HTB/cola corre DESPUES de postrouting, asi que
# ese lavado le borraria el DSCP a CAKE antes de que lo lea y romperia toda la
# clasificacion de subida.
:do {
  add action=change-dscp chain=prerouting comment="EVG-QOS2026 | WASH ENTRANTE WAN" in-interface-list=$EVGWANIF new-dscp=0 passthrough=yes
  add action=change-dscp chain=prerouting comment="EVG-QOS2026 | WASH INGRESO CLIENTE" in-interface-list=$EVGCLILIST new-dscp=0 passthrough=yes
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: fallo el WASH de DSCP." }


# ============================================================================
# 9.1 RECLASIFICACION POR SNI EN VIVO  (va PRIMERO a proposito)
# ============================================================================
# Estas reglas NO llevan connection-state=new: actuan sobre el ClientHello, que
# es el paquete donde recien aparece el SNI. Sin esto, la PRIMERA conexion a un
# servidor se clasifica como WEB o GENERAL, porque el SYN llega antes que el
# SNI. En un speedtest ese es exactamente el caso que importa: el test arranca
# frio, con la lista sin poblar.
#
# [R6-07] El acotamiento a los primeros 20 KB y a tcp/443 se hace UNA VEZ en la
# regla de entrada, no en cada regla.
:if ($EVGSNILIVE = "si") do={
  :do {
    add action=jump chain=prerouting jump-target=EVG-SNILIVE protocol=tcp dst-port=443 connection-bytes=0-20000 in-interface-list=$EVGCLILIST comment="EVG-QOS2026 | GATE -> cadena EVG-SNILIVE (solo el arranque de cada conexion 443)"
  } on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudo crear el GATE de SNI en vivo." }

  # --- SPEEDTEST (lo mas importante) ---------------------------------------
  :do { :foreach h in={"*.ookla.com";"*.speedtest.net";"*.speedtestcustom.com";"*.nperf.com";"speed.cloudflare.com";"*.librespeed.org";"*.measurementlab.net";"*.openspeedtest.com"} do={
    add action=mark-connection chain=EVG-SNILIVE comment="EVG-QOS2026-ST | SNI LIVE SPEEDTEST" new-connection-mark=SPEEDTEST passthrough=no tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  # --- VIDEO (que no arranque en tin 2 y despues baje) ---------------------
  :do { :foreach h in={"*youtube.com*";"*googlevideo.com*"} do={
    add action=mark-connection chain=EVG-SNILIVE comment="EVG-QOS2026 | SNI LIVE YOUTUBE" new-connection-mark=STREAMING-YT passthrough=no tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  :do { :foreach h in={"*netflix*";"*nflxvideo*";"*.disneyplus.com";"*primevideo*";"*.amazonvideo.com";"*.max.com"} do={
    add action=mark-connection chain=EVG-SNILIVE comment="EVG-QOS2026 | SNI LIVE STREAMING" new-connection-mark=STREAMING passthrough=no tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  # --- CONFERENCIA ---------------------------------------------------------
  :do { :foreach h in={"*.zoom.us";"*.meet.google.com";"teams.microsoft.com"} do={
    add action=mark-connection chain=EVG-SNILIVE comment="EVG-QOS2026 | SNI LIVE PROD" new-connection-mark=PRODUCTIVIDAD passthrough=no tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
  # --- BULK (que la actualizacion no arranque en tin 2) --------------------
  :do { :foreach h in={"*.windowsupdate.com";"*.delivery.mp.microsoft.com";"*.steamcontent.com";"*.playstation.net";"*.xboxlive.com";"*.epicgames.com"} do={
    add action=mark-connection chain=EVG-SNILIVE comment="EVG-QOS2026 | SNI LIVE BULK" new-connection-mark=BULK passthrough=no tls-host=$h
  } } on-error={ :set EVGERR ($EVGERR + 1) }
}


# ============================================================================
# 9.2 MARK-CONNECTION  (de MAYOR a MENOR confianza)
# ============================================================================
# [R6-07] Una sola regla de entrada con connection-state=new y la interface-list.
# Todo lo demas vive en la cadena EVG-MARK, que solo recorren los paquetes que
# ABREN una conexion. En R5 cada paquete de una descarga en curso recorria las
# ~45 reglas para terminar descartado por connection-state.
:do {
  add action=jump chain=prerouting jump-target=EVG-MARK connection-state=new in-interface-list=$EVGCLILIST comment="EVG-QOS2026 | GATE -> cadena EVG-MARK (solo conexiones nuevas de clientes)"
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudo crear el GATE de marcado. SIN ESTO NO SE CLASIFICA NADA." }

# --- SPEEDTEST PRIMERO, para que nada mas lo reclame ------------------------
# 1) servidor on-net declarado a mano. NO lleva restriccion de WAN porque
#    justamente ese trafico no sale del ISP.
# 2) servidores publicos detectados por SNI
# 3) puerto Ookla clasico sin TLS. Amplio a proposito: es preferible un falso
#    positivo en tin 2 (best effort) a que el test se auto-degrade.
# 4) Ookla legacy en 5060/TCP: DESHABILITADA, choca con SIP sobre TCP.
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026-ST | MARK SPEEDTEST LOCAL" dst-address-list=SPEEDTEST-LOCAL new-connection-mark=SPEEDTEST passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026-ST | MARK SPEEDTEST" dst-address-list=SPEEDTEST-SERVERS new-connection-mark=SPEEDTEST passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026-ST | MARK SPEEDTEST 8080" dst-port=8080 new-connection-mark=SPEEDTEST passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK disabled=yes comment="EVG-QOS2026-ST | MARK SPEEDTEST 5060 legacy (CHOCA CON SIP TCP)" dst-port=5060 new-connection-mark=SPEEDTEST passthrough=no protocol=tcp
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: fallo el bloque SPEEDTEST." }

# --- Control critico -------------------------------------------------------
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | DNS UDP" dst-port=53 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | DNS TCP" dst-port=53 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | DOT" dst-port=853 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | ICMP" new-connection-mark=CONTROL-CRITICO passthrough=no protocol=icmp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | SIP UDP" dst-port=5060-5062 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | SIP TCP/TLS" dst-port=5060-5062 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | ADMIN WINBOX" dst-port=$EVGWINBOXQ new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: fallo el bloque CONTROL-CRITICO." }

# --- IPTV multicast (opt-in) ------------------------------------------------
:if ($EVGIPTV = "si") do={
  :do {
    add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | IGMP" new-connection-mark=CONTROL-CRITICO passthrough=no protocol=igmp
    add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | IPTV MULTICAST" dst-address=224.0.0.0/4 new-connection-mark=PRODUCTIVIDAD passthrough=no
  } on-error={ :set EVGERR ($EVGERR + 1) }
}

# --- BULK por SNI ----------------------------------------------------------
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | BULK CDN" dst-address-list=BULK-CDN new-connection-mark=BULK passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- Productividad ---------------------------------------------------------
# El 25/TCP quedo FUERA a proposito: EVG-FW2026 lo dropea de salida (anti-spam)
# y priorizarlo aca solo priorizaba trafico de botnet.
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | MEET" dst-address-list=MEET-GOOGLE new-connection-mark=PRODUCTIVIDAD passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | HANGOUTS" dst-address-list=HANGOUTS-GOOGLE new-connection-mark=PRODUCTIVIDAD passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | CLASSROOM" dst-address-list=CLASSROOM new-connection-mark=PRODUCTIVIDAD passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | ZOOM" dst-address-list=ZOOM new-connection-mark=PRODUCTIVIDAD passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | OFFICE365" dst-address-list=OFFICE365 new-connection-mark=PRODUCTIVIDAD passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | CORREO" dst-port=110,143,465,587,993,995 new-connection-mark=PRODUCTIVIDAD passthrough=no protocol=tcp
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- Mensajeria ------------------------------------------------------------
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | WA SNI" dst-address-list=WA-WEB new-connection-mark=MENSAJERIA passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | WA TCP" dst-port=5222,5223,5228,4244 new-connection-mark=MENSAJERIA passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | WA UDP" dst-port=3478-3481 new-connection-mark=MENSAJERIA passthrough=no protocol=udp
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- Streaming -------------------------------------------------------------
# Sin protocol=: asi tambien captura el QUIC (UDP/443) hacia esas mismas IP.
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | YOUTUBE" dst-address-list=YOUTUBE new-connection-mark=STREAMING-YT passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | NETFLIX" dst-address-list=NETFLIX new-connection-mark=STREAMING passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | DISNEY" dst-address-list=DISNEY-PLUS new-connection-mark=STREAMING passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | AMAZON VIDEO" dst-address-list=AMAZON-VIDEO new-connection-mark=STREAMING passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | HBO MAX" dst-address-list=HBO-MAX new-connection-mark=STREAMING passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | DIRECTV GO" dst-address-list=DIRECTGO new-connection-mark=STREAMING passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- Redes sociales --------------------------------------------------------
# Van a tin 2 (CS0) igual que la web. Es a proposito: el video corto de
# TikTok/Reels es sensible al arranque y NO tolera tin 1 ni la degradacion por
# volumen. Este es el punto que explicaba los reportes de "se pega".
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | FACEBOOK" dst-address-list=FACEBOOK new-connection-mark=REDES-SOCIALES passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | INSTAGRAM" dst-address-list=INSTAGRAM new-connection-mark=REDES-SOCIALES passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | TIKTOK" dst-address-list=TIKTOK new-connection-mark=REDES-SOCIALES passthrough=no
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | TWITTER X" dst-address-list=TWITTER new-connection-mark=REDES-SOCIALES passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- RTP y gaming ----------------------------------------------------------
# *** ADVERTENCIA: rangos anchos = falsos positivos hacia tin 5/6, donde el
# umbral es BAJO. Los tres peores son 5000-5500 (LoL), 7000-7999 (Free Fire) y
# 16000-17000 (RTP). Si ves trafico raro en tin 5/6, estrecha ESTOS rangos.
# [R6-08] pone una red de contencion por volumen mas abajo, en 9.3.
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | RTP" dst-port=16000-17000 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | GAMING TCP" dst-port=3013,10012,25565,7889,3074,3097,3659,9988 new-connection-mark=GAMING passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | CLASH COC" dst-port=9330-9340 new-connection-mark=GAMING passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | GAMING UDP" dst-port=8011,9030,10491,19132,19133,3074,88,3544,3659,1200,3097,6672 new-connection-mark=GAMING passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | STEAM JUEGO" dst-port=27000-27050 new-connection-mark=GAMING passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | FORTNITE" dst-port=9000-9100 new-connection-mark=GAMING passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | VALORANT" dst-port=8393-8400 new-connection-mark=GAMING passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | GTA ONLINE" dst-port=61455-61458 new-connection-mark=GAMING passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | LOL" dst-port=5000-5500 new-connection-mark=GAMING passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | FREE FIRE" dst-port=7000-7999 new-connection-mark=GAMING passthrough=no protocol=udp
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- Catch-all -------------------------------------------------------------
:do {
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | WEB GENERAL" dst-port=80,443,8443 new-connection-mark=NAVEGACION-WEB passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | QUIC HTTP3" dst-port=443,80 new-connection-mark=NAVEGACION-WEB passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK comment="EVG-QOS2026 | RESTO" connection-mark=no-mark new-connection-mark=TRAFICO-GENERAL passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }


# ============================================================================
# 9.3 CHANGE-DSCP  -> la prioridad real que CAKE lee
# ============================================================================
# [R6-08] RED DE CONTENCION PARA tin 5 / tin 6  (va PRIMERO, por passthrough=no)
#
# El problema que R5 solo documentaba: los rangos anchos de gaming (5000-5500,
# 7000-7999, 9000-9100, 27000-27050) y el rango RTP 16000-17000 atrapan trafico
# que no es una partida ni una llamada. Y en CAKE eso no es neutro: los tines
# altos tienen umbral BAJO, asi que un flujo pesado ahi se AUTOCASTIGA -- y de
# paso empuja a la voz real.
#
# La deteccion es por TASA (connection-rate), no por bytes acumulados:
#   - una partida son decenas de kbps; una llamada RTP, 100 kbps
#   - una descarga por el mismo puerto son megabits sostenidos
# La tasa se mide sobre los ultimos segundos, asi que esto es REVERSIBLE: si el
# flujo baja de nuevo, vuelve a su clase. Es la diferencia con la regla de
# elefante, que degrada por bytes acumulados y no vuelve nunca.
# Poner $EVGGAMERATE / $EVGEFRATE en "0" desactiva cada una.
:if ($EVGGAMERATE != "0") do={
  :do {
    add action=change-dscp chain=forward comment="EVG-QOS2026 | ANTI-FALSO-POSITIVO GAMING (tasa alta -> tin2)" connection-mark=GAMING connection-rate=($EVGGAMERATE . "-4294967295") new-dscp=0 passthrough=no
  } on-error={ :set EVGERR ($EVGERR + 1); :log warning "EVG-QOS2026: este build no acepta connection-rate; el desascenso de GAMING queda sin aplicar." }
}
:if ($EVGEFRATE != "0") do={
  :do {
    add action=change-dscp chain=forward comment="EVG-QOS2026 | ANTI-FALSO-POSITIVO EF (tasa alta -> tin2)" connection-mark=CONTROL-CRITICO connection-rate=($EVGEFRATE . "-4294967295") new-dscp=0 passthrough=no
  } on-error={ :set EVGERR ($EVGERR + 1) }
}

:do {
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin6 EF CONTROL" connection-mark=CONTROL-CRITICO new-dscp=46 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin5 CS2 GAMING" connection-mark=GAMING new-dscp=16 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin3 AF41 PRODUCTIVIDAD" connection-mark=PRODUCTIVIDAD new-dscp=34 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin3 AF31 MENSAJERIA" connection-mark=MENSAJERIA new-dscp=26 passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- tin 2: best effort, umbral 100% ---------------------------------------
# El speedtest vive aca A PROPOSITO. No se sube a tin 6: en tin 6 el umbral es
# minimo y un test que satura se auto-degrada. El objetivo se logra bajando lo
# pesado (BULK), no subiendo el test.
:do {
  add action=change-dscp chain=forward comment="EVG-QOS2026-ST | tin2 CS0 SPEEDTEST" connection-mark=SPEEDTEST new-dscp=0 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin2 CS0 SOCIAL" connection-mark=REDES-SOCIALES new-dscp=0 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin2 CS0 WEB" connection-mark=NAVEGACION-WEB new-dscp=0 passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- tin 1: streaming largo (bufferea, puede ceder) ------------------------
:do {
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin1 AF11 YOUTUBE" connection-mark=STREAMING-YT new-dscp=10 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin1 AF11 STREAMING" connection-mark=STREAMING new-dscp=10 passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- tin 0: background  ([R6-06]: puede caer en tin 1 segun build de CAKE) --
:do {
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin0 CS1 BULK" connection-mark=BULK new-dscp=$EVGDSCPBULK passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }

# --- Flujo elefante: creada pero DESHABILITADA -----------------------------
# CAKE con triple-isolate ya reparte entre flujos dentro de la cola del cliente.
# Esta regla degrada por bytes acumulados, o sea de forma IRREVERSIBLE mientras
# viva la conexion, y es la que produce "el video se pega" y "el test mide de
# menos" cuando el umbral queda corto. Activar SOLO con un problema de P2P
# medido:  /ip firewall mangle enable [find comment~"ELEFANTE"]
# [R6-04] Ahora si usa $EVGELEBYTES.
:do {
  :if ($EVGELEFANTE = "si") do={
    add action=change-dscp chain=forward comment="EVG-QOS2026 | tin0 CS1 ELEFANTE" connection-bytes=($EVGELEBYTES . "-0") connection-mark=TRAFICO-GENERAL new-dscp=$EVGDSCPBULK passthrough=no
  } else={
    add action=change-dscp chain=forward disabled=yes comment="EVG-QOS2026 | tin0 CS1 ELEFANTE (OPT-IN)" connection-bytes=($EVGELEBYTES . "-0") connection-mark=TRAFICO-GENERAL new-dscp=$EVGDSCPBULK passthrough=no
  }
} on-error={ :set EVGERR ($EVGERR + 1) }

:do {
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin2 CS0 GENERAL" connection-mark=TRAFICO-GENERAL new-dscp=0 passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }


# ============================================================================
# 9.4 TRAFICO ORIGINADO EN EL ROUTER (chain=output)
# ============================================================================
# Las respuestas del resolver DNS del propio router, el ICMP y la gestion salen
# por output y NUNCA pasan por forward. Sin esto, el DNS que mas usan los
# clientes es el unico servicio que queda sin prioridad.
#
# [R6-11] Acotadas con out-interface-list=$EVGCLILIST: en R5 tambien marcaban EF
# el DNS y el ICMP que el router manda HACIA EL UPSTREAM, que no se conforma en
# ninguna cola de cliente y solo exporta DSCP a un transito ajeno.
# Si la lista de clientes esta vacia estas reglas cuentan cero (igual que el
# resto del script).
:do {
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT DNS UDP -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=udp src-port=53
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT DNS TCP -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=tcp src-port=53
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT DOT -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=tcp src-port=853
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT WINBOX -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=tcp src-port=$EVGWINBOXQ
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT ICMP -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=icmp
} on-error={ :set EVGERR ($EVGERR + 1); :log warning "EVG-QOS2026: fallo el bloque de chain=output (DNS del router sin prioridad)." }


# ============================================================================
# SECCION 10 - MANGLE IPv6 (espejo)
# ============================================================================
# *** LEER [R6-10] ANTES DE CONFIAR EN ESTA SECCION ***
# Clasificar IPv6 solo sirve si el trafico IPv6 del cliente ENTRA A UNA COLA.
# Con colas dinamicas de PPP (target = IP v4) NO entra: se clasifica y sale sin
# conformar. La guarda de la SECCION 0B avisa si ese es tu caso.
/ipv6 firewall mangle

:do {
  add action=change-dscp chain=prerouting comment="EVG-QOS2026 | WASH V6 WAN" in-interface-list=$EVGWANIF new-dscp=0 passthrough=yes
  add action=change-dscp chain=prerouting comment="EVG-QOS2026 | WASH V6 CLIENTE" in-interface-list=$EVGCLILIST new-dscp=0 passthrough=yes
} on-error={ :set EVGERR ($EVGERR + 1) }

:if ($EVGSNILIVE = "si") do={
  :do {
    add action=jump chain=prerouting jump-target=EVG-SNILIVE-V6 protocol=tcp dst-port=443 connection-bytes=0-20000 in-interface-list=$EVGCLILIST comment="EVG-QOS2026 | GATE V6 -> cadena EVG-SNILIVE-V6"
    :foreach h in={"*.ookla.com";"*.speedtest.net";"*.speedtestcustom.com";"speed.cloudflare.com"} do={
      add action=mark-connection chain=EVG-SNILIVE-V6 comment="EVG-QOS2026-ST | SNI LIVE SPEEDTEST V6" new-connection-mark=SPEEDTEST passthrough=no tls-host=$h
    }
    :foreach h in={"*youtube.com*";"*googlevideo.com*"} do={
      add action=mark-connection chain=EVG-SNILIVE-V6 comment="EVG-QOS2026 | SNI LIVE YOUTUBE V6" new-connection-mark=STREAMING-YT passthrough=no tls-host=$h
    }
  } on-error={ :set EVGERR ($EVGERR + 1); :log warning "EVG-QOS2026: este build no acepta tls-host en /ipv6 firewall mangle; SNI en vivo IPv6 apagado." }
}

:do {
  add action=jump chain=prerouting jump-target=EVG-MARK-V6 connection-state=new in-interface-list=$EVGCLILIST comment="EVG-QOS2026 | GATE V6 -> cadena EVG-MARK-V6"
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudo crear el GATE de marcado IPv6." }

:do {
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026-ST | MARK SPEEDTEST V6" dst-address-list=SPEEDTEST-V6 new-connection-mark=SPEEDTEST passthrough=no
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026-ST | MARK SPEEDTEST V6 8080" dst-port=8080 new-connection-mark=SPEEDTEST passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | DNS V6 UDP" dst-port=53 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | DNS V6 TCP" dst-port=53 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | DOT V6" dst-port=853 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | ICMPV6" new-connection-mark=CONTROL-CRITICO passthrough=no protocol=icmpv6
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | SIP V6 UDP" dst-port=5060-5062 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | SIP V6 TCP" dst-port=5060-5062 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | ADMIN WINBOX V6" dst-port=$EVGWINBOXQ new-connection-mark=CONTROL-CRITICO passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | BULK V6" dst-address-list=BULK-V6 new-connection-mark=BULK passthrough=no
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | PROD V6" dst-address-list=PRODUCTIVIDAD-V6 new-connection-mark=PRODUCTIVIDAD passthrough=no
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | CORREO V6" dst-port=110,143,465,587,993,995 new-connection-mark=PRODUCTIVIDAD passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | WA V6 SNI" dst-address-list=WHATSAPP-V6 new-connection-mark=MENSAJERIA passthrough=no
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | WA V6 TCP" dst-port=5222,5223,5228,4244 new-connection-mark=MENSAJERIA passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | WA V6 UDP" dst-port=3478-3481 new-connection-mark=MENSAJERIA passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | YOUTUBE V6" dst-address-list=YOUTUBE-V6 new-connection-mark=STREAMING-YT passthrough=no
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | STREAMING V6" dst-address-list=STREAMING-V6 new-connection-mark=STREAMING passthrough=no
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | SOCIAL V6" dst-address-list=SOCIAL-V6 new-connection-mark=REDES-SOCIALES passthrough=no
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | RTP V6" dst-port=16000-17000 new-connection-mark=CONTROL-CRITICO passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | GAMING V6 TCP" dst-port=3013,10012,25565,9330-9340,3074,3097,3659 new-connection-mark=GAMING passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | GAMING V6 UDP" dst-port=7000-7999,9000-9100,8393-8400,27000-27050,3074,88 new-connection-mark=GAMING passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | WEB V6" dst-port=80,443,8443 new-connection-mark=NAVEGACION-WEB passthrough=no protocol=tcp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | QUIC V6" dst-port=443,80 new-connection-mark=NAVEGACION-WEB passthrough=no protocol=udp
  add action=mark-connection chain=EVG-MARK-V6 comment="EVG-QOS2026 | RESTO V6" connection-mark=no-mark new-connection-mark=TRAFICO-GENERAL passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: fallo el marcado IPv6." }

:if ($EVGGAMERATE != "0") do={
  :do {
    add action=change-dscp chain=forward comment="EVG-QOS2026 | ANTI-FALSO-POSITIVO GAMING V6" connection-mark=GAMING connection-rate=($EVGGAMERATE . "-4294967295") new-dscp=0 passthrough=no
  } on-error={}
}
:if ($EVGEFRATE != "0") do={
  :do {
    add action=change-dscp chain=forward comment="EVG-QOS2026 | ANTI-FALSO-POSITIVO EF V6" connection-mark=CONTROL-CRITICO connection-rate=($EVGEFRATE . "-4294967295") new-dscp=0 passthrough=no
  } on-error={}
}
:do {
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin6 EF V6" connection-mark=CONTROL-CRITICO new-dscp=46 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin5 CS2 GAMING V6" connection-mark=GAMING new-dscp=16 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin3 AF41 PROD V6" connection-mark=PRODUCTIVIDAD new-dscp=34 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin3 AF31 MENSAJERIA V6" connection-mark=MENSAJERIA new-dscp=26 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026-ST | tin2 CS0 SPEEDTEST V6" connection-mark=SPEEDTEST new-dscp=0 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin2 CS0 SOCIAL V6" connection-mark=REDES-SOCIALES new-dscp=0 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin2 CS0 WEB V6" connection-mark=NAVEGACION-WEB new-dscp=0 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin1 AF11 YOUTUBE V6" connection-mark=STREAMING-YT new-dscp=10 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin1 AF11 STREAMING V6" connection-mark=STREAMING new-dscp=10 passthrough=no
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin0 CS1 BULK V6" connection-mark=BULK new-dscp=$EVGDSCPBULK passthrough=no
} on-error={ :set EVGERR ($EVGERR + 1) }
:do {
  :if ($EVGELEFANTE = "si") do={
    add action=change-dscp chain=forward comment="EVG-QOS2026 | tin0 CS1 ELEFANTE V6" connection-bytes=($EVGELEBYTES . "-0") connection-mark=TRAFICO-GENERAL new-dscp=$EVGDSCPBULK passthrough=no
  } else={
    add action=change-dscp chain=forward disabled=yes comment="EVG-QOS2026 | tin0 CS1 ELEFANTE V6 (OPT-IN)" connection-bytes=($EVGELEBYTES . "-0") connection-mark=TRAFICO-GENERAL new-dscp=$EVGDSCPBULK passthrough=no
  }
} on-error={}
:do {
  add action=change-dscp chain=forward comment="EVG-QOS2026 | tin2 CS0 GENERAL V6" connection-mark=TRAFICO-GENERAL new-dscp=0 passthrough=no
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT DNS V6 UDP -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=udp src-port=53
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT DNS V6 TCP -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=tcp src-port=53
  add action=change-dscp chain=output comment="EVG-QOS2026 | OUT ICMPV6 -> EF" new-dscp=46 out-interface-list=$EVGCLILIST passthrough=no protocol=icmpv6
} on-error={ :set EVGERR ($EVGERR + 1) }


# ============================================================================
# SECCION 11 - REPORTE Y MANTENIMIENTO PROGRAMADOS
# ============================================================================
# Sin `owner=`: R5 ponia owner=admin y en un equipo donde el usuario admin no
# existe (renombrado por politica) el add falla y, con el import cortando en el
# primer error, se pierde todo lo que viene despues.
/system script
:do {
add name=EVG-QOS-REPORT policy=read,write,test source={
:log warning "=== EVG-QOS-REPORTE ==="
:if ([:len [/ip firewall filter find where action="fasttrack-connection" and disabled=no]] > 0) do={
  :log error "EVG-QOS-REPORTE: FASTTRACK ACTIVO -> el QoS no esta funcionando."
}
# --- la puerta de entrada: si esta en cero, no se clasifica NADA ------------
:local gate 0
:foreach r in=[/ip firewall mangle find where comment~"GATE -> cadena EVG-MARK"] do={
  :set gate ($gate + [/ip firewall mangle get $r packets])
}
:if ($gate = 0) do={
  :log error "EVG-QOS-REPORTE: la regla GATE de marcado esta en CERO -> la interface-list de clientes esta mal o vacia. NADA se esta clasificando."
} else={
  :log info ("EVG-QOS-REPORTE: paquetes que entraron a clasificacion = " . $gate)
}
# --- speedtest --------------------------------------------------------------
:local st 0
:foreach r in=[/ip firewall mangle find where comment~"EVG-QOS2026-ST"] do={
  :set st ($st + [/ip firewall mangle get $r packets])
}
:if ($st = 0) do={
  :log warning "EVG-QOS-REPORTE: CERO paquetes de SPEEDTEST clasificados. Normal si nadie midio hoy; si el cliente dice que midio, revisar SPEEDTEST-LOCAL y la interface-list."
} else={
  :log warning ("EVG-QOS-REPORTE: paquetes clasificados como SPEEDTEST = " . $st)
}
# --- contadores por clase ---------------------------------------------------
:foreach r in=[/ip firewall mangle find where comment~"tin" and comment~"EVG-QOS2026"] do={
  :local c [/ip firewall mangle get $r comment]
  :local p [/ip firewall mangle get $r packets]
  :log info ("EVG-QOS-REPORTE: " . $c . " -> " . $p . " pkt")
}
# --- falsos positivos que se estan corrigiendo solos ------------------------
:local fp 0
:foreach r in=[/ip firewall mangle find where comment~"ANTI-FALSO-POSITIVO"] do={
  :set fp ($fp + [/ip firewall mangle get $r packets])
}
:if ($fp > 0) do={
  :log warning ("EVG-QOS-REPORTE: " . $fp . " pkt desascendidos de tin5/tin6 por tasa alta. Si el numero es grande, estrechar los rangos de puertos de gaming/RTP.")
}
# --- coherencia del conformador --------------------------------------------
:if ([:len [/queue type find where name="EVG-CAKE2026"]] = 0) do={
  :log error "EVG-QOS-REPORTE: NO existe el queue type EVG-CAKE2026."
} else={
  :local oh [/queue type get [/queue type find where name="EVG-CAKE2026"] cake-overhead]
  :local mp [/queue type get [/queue type find where name="EVG-CAKE2026"] cake-mpu]
  :if (($oh >= 38 and $mp != 84) or ($oh < 38 and $mp != 64)) do={
    :log error ("EVG-QOS-REPORTE: overhead=" . $oh . " y mpu=" . $mp . " son de escuelas distintas. Escuela A -> mpu 64, escuela B -> mpu 84.")
  }
}
# --- colas ------------------------------------------------------------------
:local qn 0
:local qsin 0
:local qtot 0
:foreach q in=[/queue simple find where !dynamic] do={
  :set qtot ($qtot + 1)
  :do {
    :if (!([:tostr [/queue simple get $q queue]]~"EVG-CAKE2026")) do={ :set qn ($qn + 1) }
    :local ml [:tostr [/queue simple get $q max-limit]]
    :if ($ml = "" or $ml = "0/0") do={ :set qsin ($qsin + 1) }
  } on-error={}
}
:if ($qn > 0) do={ :log warning ("EVG-QOS-REPORTE: " . $qn . " de " . $qtot . " colas simples NO usan EVG-CAKE2026.") }
:if ($qsin > 0) do={ :log warning ("EVG-QOS-REPORTE: " . $qsin . " cola(s) sin max-limit: no conforman nada.") }
# --- IPv6 sin cola ----------------------------------------------------------
:local v6 0
:local q6 0
:do { :if ([:len [/ipv6 address find where disabled=no and !link-local]] > 0) do={ :set v6 1 } } on-error={}
:foreach q in=[/queue simple find] do={
  :do { :if ([:tostr [/queue simple get $q target]]~":") do={ :set q6 1 } } on-error={}
}
:if ($v6 = 1 and $q6 = 0) do={
  :log error "EVG-QOS-REPORTE: hay IPv6 y ninguna cola con target IPv6 -> el trafico IPv6 de los clientes NO se conforma."
}
# --- servidores de medicion -------------------------------------------------
:local nAuto [:len [/ip firewall address-list find where list="SPEEDTEST-LOCAL-AUTO"]]
:local nLoc  [:len [/ip firewall address-list find where list="SPEEDTEST-LOCAL" and disabled=no]]
:log warning ("EVG-QOS-REPORTE: servidores 8080 detectados=" . $nAuto . " | declarados en SPEEDTEST-LOCAL=" . $nLoc)
:local cpu [/system resource get cpu-load]
:log warning ("EVG-QOS-REPORTE: CPU=" . $cpu . "% | colas simples=" . [:len [/queue simple find]])
:if ($cpu > 70) do={
  :log error "EVG-QOS-REPORTE: CPU sostenida por encima de 70%. Pasar EVGCPU a 'bajo' y reaplicar, o repartir sesiones entre equipos."
}
:log warning "=== EVG-QOS-REPORTE FIN ==="
}
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudo crear el script EVG-QOS-REPORT." }

# --- Colas y perfiles nuevos del sistema de facturacion ---------------------
# WispHub, Mikrowisp y similares crean la cola (y a veces el perfil) al dar de
# alta al cliente, con su propio queue-type. Sin esto, cada alta posterior a la
# implementacion nace SIN CAKE y no se nota hasta que alguien mira cola por
# cola. Respeta las colas con queue-type propio, igual que la SECCION 4.
:do {
add name=EVG-QOS-COLAS policy=read,write,test source={
:local n 0
:foreach q in=[/queue simple find where !dynamic] do={
  :do {
    :local qt [:tostr [/queue simple get $q queue]]
    :if ($qt~"^default" or $qt~"^pcq" or $qt~"^ethernet-default" or $qt~"^wireless-default" or $qt~"^synchronous-default" or $qt~"^hotspot-default") do={
      /queue simple set $q queue="EVG-CAKE2026/EVG-CAKE2026"
      :set n ($n + 1)
    }
  } on-error={}
}
:local p 0
:foreach f in=[/ppp profile find where rate-limit!=""] do={
  :do {
    :local qt [:tostr [/ppp profile get $f queue-type]]
    :if (!($qt~"EVG-CAKE2026")) do={
      :do { /ppp profile set $f queue-type="EVG-CAKE2026" } on-error={
        :do { /ppp profile set $f queue-type="EVG-CAKE2026/EVG-CAKE2026" } on-error={}
      }
      :set p ($p + 1)
    }
  } on-error={}
}
:if (($n + $p) > 0) do={ :log warning ("EVG-QOS-COLAS: colas nuevas a CAKE = " . $n . " | ppp profiles corregidos = " . $p) }
}
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudo crear el script EVG-QOS-COLAS." }

/system scheduler
:do {
  add name=EVG-QOS-REPORT on-event=EVG-QOS-REPORT interval=1d start-time=08:05:00 policy=read,write,test comment="EVG-QOS2026 | Reporte diario 8:05"
  add name=EVG-QOS-COLAS on-event=EVG-QOS-COLAS interval=1h start-time=startup policy=read,write,test comment="EVG-QOS2026 | Convierte a CAKE las colas y perfiles nuevos del facturador"
} on-error={ :set EVGERR ($EVGERR + 1); :log error "EVG-QOS2026: no se pudieron crear los schedulers." }


# ============================================================================
# SECCION 12 - PURGA DE CONNTRACK  (opcional)
# ============================================================================
# Las conexiones YA establecidas no tienen connection-mark y las reglas de
# marcado usan connection-state=new: nunca se van a marcar. Hasta que expiren,
# el QoS trabaja a ciegas sobre ellas y el primer reporte miente.
#
# La purga selectiva NO corta descargas ya clasificadas: solo saca de la tabla
# lo que no tiene marca, y esas conexiones se vuelven a crear en el siguiente
# paquete (TCP no se entera; en el peor caso hay un reintento).
:if ($EVGPURGA = "si") do={
  :do {
    :local n [:len [/ip firewall connection find where connection-mark="no-mark"]]
    /ip firewall connection remove [find where connection-mark="no-mark"]
    :log warning ("EVG-QOS2026: purga selectiva de conntrack -> " . $n . " conexiones sin marca eliminadas para que se reclasifiquen.")
  } on-error={ :log warning "EVG-QOS2026: no se pudo purgar conntrack." }
} else={
  :log info "EVG-QOS2026: purga de conntrack NO ejecutada (EVGPURGA=no). Hacerla a mano: /ip firewall connection remove [find where connection-mark=\"no-mark\"]"
}


# ============================================================================
# CIERRE
# ============================================================================
:if ($EVGERR > 0) do={
  :log error ("EVG-QOS2026-R6: TERMINO CON " . $EVGERR . " BLOQUE(S) FALLADO(S). Buscar las lineas 'fallo' o 'no se pudo' en el log ANTES de dar el trabajo por hecho.")
} else={
  :log warning "EVG-QOS2026-R6: aplicacion completa, 0 bloques fallados."
}

# --- Limpieza de variables globales de control ------------------------------
:set abortar
:set lim
:set limm
:set sinrl
:set tocadas
:set saltadas
:set agrupa
:set sinlim
:set nCli
:set rosver
:set pplSet
:set pplOtra
:set qtOK
:set qtNO
:set EVGMPU
:set EVGNATQ
:set EVGWASHQ
:set EVGSNIFULL
:set EVGnWan
:set EVGnLan
:set EVGvlanCli
:set EVGqinq
:set EVGhayDhcp
:set EVGpcc
:set EVGv6
:set EVGq6
:set EVGERR

:log warning "EVG-QOS2026-R6: APLICACION COMPLETADA"


# ============================================================================
# VERIFICACION POST-DEPLOY
# ============================================================================
#  [ ] /log print where message~"EVG-QOS2026"
#        -> la linea de cierre tiene que decir "0 bloques fallados"
#  [ ] /interface list member print where list=EVG-CLIENTES
#        -> con PPPoE se llena solo al reconectar sesiones. Si sigue vacia a
#           los pocos minutos, el ppp profile no tomo interface-list.
#  [ ] /ip firewall mangle print stats where comment~"GATE -> cadena EVG-MARK"
#        -> si esta en CERO, la interface-list esta mal y NADA se clasifica.
#           Es el primer contador que hay que mirar, antes que cualquier otro.
#  [ ] /ip firewall mangle print stats where comment~"RESTO"
#  [ ] /ip firewall mangle print stats where comment~"WASH ENTRANTE"
#  [ ] /ip firewall raw print stats where comment~"GATE -> cadena EVG-SNI"
#  [ ] /ip firewall address-list print count-only where list=YOUTUBE
#        -> debe crecer en minutos si hay navegacion
#  [ ] /queue type print where name=EVG-CAKE2026
#  [ ] /ip firewall filter print where action="fasttrack-connection"
#        -> vacio o deshabilitado
#  [ ] /system script run EVG-QOS-REPORT ; /log print where message~"EVG-QOS-REPORTE"
#
# PRUEBA DEL CASO SPEEDTEST (el que importa)
#  1. /ip firewall connection remove [find where connection-mark="no-mark"]
#  2. Correr el speedtest desde un cliente real (no desde el router)
#  3. Durante el test:
#       /ip firewall mangle print stats where comment~"SPEEDTEST"
#         -> alguna de las reglas debe estar contando
#       /ip firewall mangle print stats where comment~"ELEFANTE"
#         -> debe estar en 0 y deshabilitada
#       /queue simple print stats where name~"<cliente>"
#  4. Si el resultado sigue por debajo del plan pero el ping bajo carga es
#     bueno, NO es clasificacion: es la compensacion de overhead. Subir el
#     rate-limit del plan un 5-7%.
#  5. Si el test es contra un servidor on-net y no matchea nada:
#       /ip firewall address-list print where list=SPEEDTEST-LOCAL-AUTO
#     y copiar esa IP a SPEEDTEST-LOCAL.
#
# ============================================================================
# [R6-10] IPv6: LAS DOS SALIDAS POSIBLES
# ============================================================================
# El problema: la cola simple dinamica de PPP tiene como target la IP v4. El
# trafico IPv6 del cliente no entra a esa cola y sale sin conformar.
#
# OPCION 1 (la mas simple si el facturador crea las colas):
#   que la cola del cliente tenga los DOS targets:
#     /queue simple set <cola> target=10.20.30.40/32,2803:xxxx:yyyy::/56
#   Requiere que el sistema de facturacion sepa el prefijo delegado. Con
#   colas dinamicas de PPP no se puede: hay que pasar a colas estaticas.
#
# OPCION 2 (la que escala en un ISP):
#   dejar de conformar por cola simple y pasar a QUEUE TREE con
#   packet-mark por cliente, colgado de global-out / global-in, donde la
#   clasificacion es por address-list y no por familia de direcciones.
#   Es un cambio de arquitectura, no un parche: planificarlo aparte.
#
# MIENTRAS TANTO, la opcion honesta y de bajo riesgo es DESACTIVAR IPv6 hacia
# los clientes o aceptar explicitamente que el plan solo aplica a IPv4 y que
# CAKE no controla el bufferbloat del trafico v6. Lo que NO conviene es dejar
# el espejo IPv6 clasificando y suponer que hay control: cuesta CPU y no hace
# nada.
#
# ============================================================================
# ROLLBACK COMPLETO
# ============================================================================
#  /ip firewall mangle remove [find where comment~"EVG-QOS2026"]
#  /ip firewall raw remove [find where comment~"EVG-QOS2026"]
#  /ipv6 firewall mangle remove [find where comment~"EVG-QOS2026"]
#  /ipv6 firewall raw remove [find where comment~"EVG-QOS2026"]
#  /ip firewall address-list remove [find where comment~"EVG-QOS2026"]
#  /ipv6 firewall address-list remove [find where comment~"EVG-QOS2026"]
#  /system scheduler remove [find where comment~"EVG-QOS2026"]
#  /system script remove [find where name~"EVG-QOS-"]
#  # devolver las colas a un tipo por defecto ANTES de borrar el queue type:
#  /queue simple set [find where queue~"EVG-CAKE2026"] queue=default-small/default-small
#  /ppp profile set [find where queue-type~"EVG-CAKE2026"] queue-type=default-small
#  /queue type remove [find where name="EVG-CAKE2026"]
#  # y los miembros que agrego el autodescubrimiento:
#  /interface list member remove [find where comment~"EVG-QOS2026-AUTO"]
#
# ============================================================================
# NOTAS Y LIMITES HONESTOS
# ============================================================================
#  - Fasttrack ROMPE este QoS. No lo actives sobre estas reglas.
#  - Sin conntrack no hay QoS: todo el esquema es por connection-mark.
#  - fast.com NO se prioriza: comparte infra con Netflix (Open Connect).
#    Priorizarlo por SNI arrastraria todo Netflix a la clase de speedtest.
#  - ECH (Encrypted Client Hello) oculta el SNI. A medida que se despliegue, el
#    matching por tls-host pierde efectividad y mas trafico cae en
#    NAVEGACION-WEB. Ese es el motivo real por el que la regla de elefante ya
#    no puede ser agresiva: cada vez hay mas trafico legitimo sin clasificar.
#  - QUIC en cold-start no tiene SNI legible en RouterOS; se clasifica por IP
#    (listas ya pobladas) o cae en NAVEGACION-WEB.
#  - cake-nat=no asume UNA cola POR CLIENTE. Si una cola agrupa varios clientes
#    detras de NAT, EVGNAT="auto" lo detecta y pone cake-nat=yes.
#  - El mapeo CS1 -> tin 0 depende del build de CAKE [R6-06]. Verificalo con la
#    prueba de arriba antes de prometer "las actualizaciones no molestan".
#  - COSTO DE CPU: CAKE por cola en nodos con cientos de sesiones es caro. Si
#    el CPU pasa de 70% sostenido: EVGCPU="bajo"; y si aun asi no alcanza, la
#    salida no es bajar el QoS sino repartir sesiones entre equipos o pasar a
#    un modelo de cola padre por nodo.
#  - Este QoS conforma en el BORDE. No arregla la congestion del ultimo tramo
#    (WiFi del cliente, sector de radio saturado, PON sobresuscrito).
#  - IPv6: leer [R6-10]. Clasificado no es lo mismo que conformado.
# ============================================================================
