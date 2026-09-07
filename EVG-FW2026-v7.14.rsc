# ============================================================================
# EVG-FW2026 | PLANTILLA FIREWALL ISP  (RouterOS 7.x)  --  GENERICA  v7.14
# ============================================================================
#
# ----------------------------------------------------------------------------
#  MEJORAS v7.14 SOBRE v7.13  -- menos falsos positivos + autocalibracion
#
#  El objetivo de esta version es doble: (1) que las detecciones NO marquen
#  trafico legitimo, y (2) que los umbrales de "trafico valido" se ajusten
#  SOLOS a lo que es normal en ESTA red, en vez de un numero fijo que
#  siempre queda corto en un lado y largo en el otro.
#
#  --- MENOS FALSOS POSITIVOS ---
#
#  [FP-01] *** 6969 (BitTorrent) YA NO SE MARCA COMO "INFECCION CONFIRMADA" ***
#          El 6969 es a la vez la firma de Hajime Y un puerto legitimo de
#          tracker BitTorrent. En v7.13 caia en CPE-INFECTADO junto al
#          sinkhole y el honeypot, ensuciando la lista que el script jura
#          que "no es heuristica".
#          v7.14: 48101 y 58455 (exclusivos de Mirai) siguen CONFIRMADOS.
#          El 6969 va a CPE-MIRAI-SOSPECHA (para revisar), NO a CPE-INFECTADO.
#          El drop del 6969 se mantiene (frena la emision y el listado XBL),
#          pero solo se ESCALA a confirmado si el mismo equipo aparece en
#          otra señal dura (sinkhole, honeypot u otro puerto Mirai). Esa
#          correlacion la hace EVG-CALIBRA.
#
#  [FP-02] *** DoT: se aprende que resolver es legitimo por CONSENSO ***
#          La lista DNS-OK era corta; un cliente con un resolver DoT valido
#          pero no listado caia en CPE-DOT-RARO. Un C2 lo usa UN bot; un
#          resolver legitimo lo usan MUCHOS clientes. v7.14 amplia DNS-OK y
#          EVG-CALIBRA promueve a DNS-OK cualquier destino :853 usado por
#          >= EVGDOTMINCLIENTES clientes distintos. Deja de marcarlos.
#
#  [FP-03] *** LA INFRA DE CONFIANZA NO SE AUTOBLOQUEA POR SPOOFING ***
#          El origen de un paquete se falsifica: alguien manda un paquete con
#          src=8.8.8.8 al 445 y el detector honeypot te autobloquea tu propio
#          resolver, gateway o peer BGP. v7.14 agrega la lista
#          EVG-NO-AUTOBLOCK (union de GATEWAYS, BGP-PEERS, DNS-OK, IP-PUBLICA
#          y WAN-PRIVADA) y los detectores de INPUT ya NO agregan a esas IP.
#
#  [FP-04] *** EL DETECTOR DE PROXY YA NO CONFUNDE VIDEOLLAMADAS ***
#          Una videollamada (Zoom, Meet, WhatsApp) es UN flujo grande y
#          simetrico -- y en v7.13 se marcaba como proxy. Un proxy real
#          relaya MUCHOS flujos simetricos a la vez. v7.14 cuenta los flujos
#          simetricos POR EQUIPO y solo marca al que tiene >= EVGPROXYMINFLOWS
#          (default 4); ademas sube el minimo de bytes y aprieta el factor.
#
#  --- AUTOCALIBRACION ---
#
#  [NEW-09] *** EVG-CALIBRA: los umbrales se ajustan a la red  [SECCION 9.9] ***
#          Todos los umbrales que afectan a clientes pasan a variables
#          globales con piso y techo. EVG-CALIBRA mide en UNA pasada:
#            - el cliente mas ocupado -> fija el umbral de conexiones
#              concurrentes (6B.5) en 2x lo observado, acotado a
#              [EVGCONNFLOORMIN, EVGCONNFLOORMAX]. Solo sube, o baja con
#              histeresis, para no oscilar.
#            - los destinos DoT populares -> DNS-OK (FP-02)
#            - los equipos con muchos flujos simetricos -> CPE-PROXY (FP-04)
#            - correlaciona CPE-MIRAI-SOSPECHA con señales duras (FP-01)
#          Es SEGURO: el drop de conexiones (6B.5) sigue deshabilitado, asi
#          que auto-ajustar ese umbral solo cambia una lista de deteccion,
#          nunca corta a un cliente. Todo queda acotado por piso/techo, asi
#          que un error no puede poner el umbral en 0 (bloquear todo) ni en
#          infinito (no detectar nada). Reemplaza al viejo EVG-PROXY.
#
#  NOTA DE COSTO: EVG-CALIBRA recorre la tabla de conexiones una vez por
#  hora (igual que hacia EVG-PROXY). Si la caja maneja MUCHISIMAS conexiones
#  se autolimita: por encima de EVGCONNMAXSCAN omite el conteo pesado y solo
#  avisa. Subir el intervalo o EVGCONNMAXSCAN si hace falta.
#
# ----------------------------------------------------------------------------
#  CORRECCIONES v7.13 SOBRE v7.12  -- bugs de logica encontrados en revision
#                                     (mismo estilo, misma estructura)
#
#  [FIX-43] *** LOS HONEYPOT AUTODESCUBIERTOS NUNCA SE USABAN ***
#           La regla de deteccion 6B.2 matchea dst-address-list=HONEYPOT-INTERNO,
#           pero EVG-DESCUBRE (PASO 7B) poblaba la lista EVG-HONEYPOT. Nombres
#           distintos: las dark-IP que el router elegia solo jamas llegaban a
#           la regla, asi que la mejor deteccion sin falsos positivos estaba
#           APAGADA de hecho. Solo funcionaban los honeypot cargados a mano en
#           la SECCION 2.10.
#           v7.13: TODO usa HONEYPOT-INTERNO -- PASO 7B (add y remove), PASO 7
#           (lista que debe existir), el RESUMEN y una nueva verificacion en
#           EVG-AUDIT que avisa si vuelve a desalinearse.
#
#  [FIX-44] *** LA PROTECCION BRUTE-FORCE DE PPTP ERA CODIGO MUERTO ***
#           La SECCION 5.6 aceptaba tcp/1723 ANTES del staging de la 5.7c. En
#           RouterOS la primera regla que hace match gana: el accept de 5.6
#           cortocircuitaba, y las 5 reglas de staging de PPTP (5.7c) nunca
#           veian una conexion nueva. El 1723 quedaba abierto a diccionario
#           sin ningun conteo ni baneo, justo lo que 5.7c decia evitar.
#           v7.13: se quita el accept de 1723 de la 5.6 y el staging de 5.7c
#           termina con su propio accept, igual que el patron de SSH y Winbox.
#           El GRE (datos PPTP) sigue aceptado en 5.6.
#
#  [FIX-45] *** EVG-DESCUBRE VACIABA WAN/LAN ANTE UN FALLO TRANSITORIO ***
#           PASO 1 borraba TODOS los miembros EVG-AUTO de WAN y LAN al inicio y
#           recien despues recalculaba. Si en ese momento la ruta por defecto
#           no estaba (flap del uplink, BGP reconvergiendo), no se detectaba
#           WAN y la lista quedaba VACIA hasta el siguiente ciclo -- 30 min con
#           anti-spoofing, drops de borde y el DROP FINAL de INPUT contando
#           cero. El router quedaba expuesto por una caida momentanea.
#           v7.13: se calcula primero y SOLO se reemplaza la lista si la
#           deteccion trajo al menos una interfaz; si viene vacia, se CONSERVA
#           la lista actual y se registra el error. Ademas el PASO 2 reconoce
#           como WAN lo que ya este en la interface-list WAN, no solo lo
#           detectado en este ciclo, para no reclasificar la WAN como LAN.
#
#  [FIX-46] *** IPv6 BLOQUEABA EL 7547 CONTRADICIENDO LA DECISION IPv4 ***
#           La SECCION 10 dropeaba tcp/7547 (TR-069) hacia clientes en IPv6,
#           cuando toda la logica IPv4 lo deja FUERA a proposito para no romper
#           el aprovisionamiento por ACS de toda la base. Si el ISP tiene ACS
#           alcanzable por IPv6, esa regla le cortaba la gestion.
#           v7.13: el 7547 sale del drop activo IPv6 y queda como OPT-V6-7547
#           deshabilitado, para activarlo solo quien NO use ACS sobre IPv6.
#
# ----------------------------------------------------------------------------
# CORRECCIONES SOBRE v7.6  -- todas verificadas en campo
#
# ----------------------------------------------------------------------------
#  [NEW-04] *** CASO HAJIME: 16 CPE COMPROMETIDOS EN UN SOLO ISP ***
#           Agosto 2026, INTEDCOL. Spamhaus listo dos publicas por
#           elf.mirai. La firma que reportaba era una sola: conexion TCP
#           saliente al puerto 6969.
#
#           Ese puerto no estaba en ninguna lista del firewall. Al agregarlo
#           como deteccion, en 26 horas aparecieron 16 equipos repartidos en
#           DIEZ segmentos distintos y con diez fabricantes distintos.
#
#           Lo que se agrega en v7.12:
#             - Puertos de C2 (6969, 48101, 58455) como deteccion Y bloqueo
#             - Proteccion ENTRANTE de los CPE: es lo que evita infecciones
#               nuevas, y con diez fabricantes distintos pesa mas que el
#               modelo del aparato
#             - Deteccion de propagacion LATERAL entre clientes, que el
#               borde normalmente no ve porque nunca sale a internet
#             - EVG-AUDIT-EXPOSICION: encuentra las reglas dst-nat sin
#               src-address-list, que son la via de entrada
#
#           El 7547 (TR-069) queda FUERA del bloqueo a proposito: si el ISP
#           aprovisiona CPE con un ACS, cortarlo le rompe la gestion de toda
#           la base.
#
#  [NEW-05] *** LA VIA DE ENTRADA ERA EL dst-nat SIN RESTRINGIR ***
#           En el mismo caso: seis reglas dst-nat exponian servicios de
#           administracion a TODO internet sin src-address-list. Entre ellas
#           el SSH de la OLT, un servidor con SSH en el 22 directo, y el
#           Winbox de dos clientes empresariales.
#
#           Y el cruce lo confirmo: en TRES subredes habia un equipo
#           expuesto por dst-nat y un infectado vecino. Ese es el mecanismo:
#           entra por el expuesto, escanea su propia subred, contagia.
#
#           La SECCION 9.7 lo audita solo cada 6 horas, y distingue tres
#           niveles: NAT 1:1 completo (sin dst-port ni protocol, o sea el
#           equipo entero expuesto), servicio de administracion, y
#           port-forward normal. El primero es el peor y en otro cliente
#           habia dieciseis reglas asi -- hoteles, nodos, una escuela.
#
#  [NEW-08] *** AUTODESCUBRIMIENTO: SE ACABA LA CONFIGURACION A MANO ***
#           La SECCION 9.0 deduce del propio router cuales interfaces son
#           WAN, cuales llevan clientes, y que espacio considera interno.
#
#           Eso ultimo es lo que mas fallaba: un ISP que usa 30.30.0.0/16
#           adentro tenia que acordarse de declararlo, porque no es RFC1918.
#           Ahora se captura solo como red conectada.
#
#           Metodo: WAN es la interfaz por donde sale el gateway del
#           default. LAN es la que tiene IP, no es WAN, no es /32, y tiene
#           entradas ARP -- ese ultimo filtro deja fuera los enlaces punto
#           a punto hacia otros routers. Interno es todo lo que el router
#           alcanza sin pasar por la WAN.
#
#           Corre PRIMERO en la carga inicial, y cada 30 minutos despues.
#           Solo puebla listas: no crea ni una regla.
#
#  [NEW-07] *** EL ROUTER SE CONSULTA A SI MISMO EN LAS LISTAS NEGRAS ***
#           Hasta ahora los listados se descubrian cuando llegaba el correo
#           de Spamhaus o cuando un cliente reclamaba que no le abria el
#           banco. Con la SECCION 9.8 el propio equipo pregunta cada dia.
#
#           Toma las publicas de DOS fuentes -- /ip address y los
#           to-addresses de las reglas src-nat -- porque en un ISP con NAT
#           por address-list las publicas de salida pueden no estar todas
#           asignadas al router.
#
#           Consulta all.s5h.net, zen.spamhaus.org, b.barracudacentral.org
#           y all.spamrats.com. Lo que salga listado queda en la lista
#           EVG-RBL-LISTADA con el motivo.
#
#           s5h ofrece autoservicio de retiro, asi que ese lo pide solo,
#           con src-address de la IP listada. Los otros tres se retiran a
#           mano y SOLO despues de 48h sin emision: pedirlo antes vuelve a
#           listar la IP y la segunda vez cuesta mas.
#
#  [NEW-06] *** RANGOS INTERNOS QUE NO SON RFC1918 ***
#           INTEDCOL usa 30.30.0.0/16 internamente, que NO es espacio
#           privado. Sin declararlo, el trafico entre sus propias VLAN se
#           contaba como "hacia internet" y ensuciaba la deteccion.
#           Nueva lista EVG-INTERNAS en la SECCION 2.12.
#
#
# ----------------------------------------------------------------------------
#  [FIX-42] *** EL LIMITE DE ICMP TUMBABA LA RUTA CON FAILOVER ***
#           OCURRIO EN PRODUCCION.
#
#           v7.10 (heredado de v7.6) tenia:
#             accept icmp echo-reply   limit=50,50:packet
#             accept icmp echo-request limit=50,50:packet
#             drop icmp
#
#           El echo-REPLY es la respuesta que espera check-gateway=ping.
#           Al limitarla a 50/s, en un equipo con failover + netwatch +
#           monitoreo del NOC ese umbral se supera SIN que haya ataque.
#           Las respuestas que se pasan caen al `drop icmp` de abajo, el
#           gateway aparece inalcanzable y la ruta se marca inactiva.
#           Resultado: failover disparando solo y servicio intermitente.
#
#           v7.11:
#             - echo-REPLY SIN limite. Nunca se limita: es trafico de
#               respuesta a algo que el propio router pidio.
#             - echo-REQUEST limitado a 200/s (antes 50).
#             - Lista GATEWAYS: los gateways de failover quedan exentos de
#               TODO limite, antes que cualquier otra regla de ICMP.
#             - La lista se puebla SOLA leyendo /ip route (SECCION 9.1).
#
#           REGLA GENERAL QUE SE DESPRENDE: nunca poner `limit` en una
#           regla que acepta trafico de RESPUESTA. El limite va en lo que
#           llega sin invitacion, no en lo que el router pidio.
#
#
#  [FIX-32] *** udp-timeout=30s + drop invalid en FORWARD = QUIC ROTO ***
#           PRINCIPAL SOSPECHOSO DEL INCIDENTE.
#           La SECCION 3 de v7.6 subia udp-timeout a 30s. Combinado con el
#           drop de connection-state=invalid en forward (6.1), cualquier
#           flujo UDP que pause mas de medio minuto pierde su entrada en
#           conntrack; al volver el trafico se marca INVALID y muere.
#           HTTP/3 (QUIC) va sobre UDP 443: YouTube, Netflix, Meta. Y los
#           usuarios de ALTO CONSUMO son los que mas sesiones QUIC largas
#           tienen. Encaja con "tumbo a los que consumian mas y no dejaba
#           entrar a algunas plataformas".
#           v7.10: NO se toca conntrack. El drop de invalid en forward
#           queda DESHABILITADO.
#
#  [FIX-33] *** EL DETECTOR DE BRUTE-FORCE SALIENTE BANEABA A TODOS ***
#           v7.6 seccion 6.7:
#             action=add-src-to-address-list dst-port=22,23,3389
#                    limit=20,30:packet -> CPE-BRUTEFORCE
#           `limit` hace MATCH MIENTRAS SE ESTA POR DEBAJO del umbral, y
#           ademas cuenta GLOBAL, no por cliente. Logica invertida: el
#           primer SYN de un cliente legitimo lo baneaba; el que realmente
#           hacia brute-force, al pasarse, dejaba de matchear y NO entraba.
#           v7.10: cadena con dst-limit y mode=src-address.
#
#  [FIX-34] *** LISTAS ALLOWLIST QUE NUNCA SE CREABAN ***
#           SSH-ALLOWED, RDP-ALLOWED, DB-ALLOWED y SMTP-ALLOWED solo
#           existian si se descomentaban los $ADDONCE. Venian comentados.
#           En RouterOS `!LISTA-VACIA` matchea SIEMPRE.
#           Resultado: SQL saliente bloqueado a TODOS (6.5), y combinado
#           con FIX-33, SSH y RDP salientes muertos para todo el mundo.
#           v7.10: se crean con placeholder 127.0.0.1.
#
#  [FIX-35] *** connection-limit: el comentario decia 500, el valor 1000 ***
#           Unificado en 500.
#
#  [FIX-36] *** LAS EXCEPCIONES IBAN DESPUES DE LOS DETECTORES ***
#           En v7.6 el detector honeypot y el PSD (5.1) corrian ANTES de
#           las excepciones de BGP-PEERS y WAN-PRIVADA (5.1b). Un peer BGP
#           o el gateway del upstream que tocara cualquiera de esos puertos
#           quedaba en PORT-SCAN 7 dias, con la sesion BGP caida.
#           v7.10: excepciones ARRIBA, y ACOTADAS (v7.6 aceptaba TODO TCP
#           desde esas listas, dejando Winbox y SSH alcanzables desde el
#           gateway del upstream).
#
#  [FIX-37] *** DETECTOR HONEYPOT: 7 DIAS POR UN SOLO PAQUETE ***
#           El origen de un paquete se falsifica facil. Alguien manda un
#           paquete con origen 8.8.8.8 al puerto 445 y te autobloqueas
#           Google una semana.
#           v7.10: baja a 1 dia y se documenta el riesgo.
#
#  [FIX-38] *** SPAMHAUS SIN VALIDACION DE CORDURA ***
#           Si el fetch trae un archivo parcial, la lista queda incompleta
#           o con basura, y se bloquean destinos legitimos sin que nadie se
#           entere. v7.10: valida que el conteo este en un rango razonable
#           antes de reemplazar la lista buena.
#
#  [FIX-39] *** IPv6 SIN RUTEO ***
#           v7.6 no aceptaba OSPFv3 ni BGP sobre IPv6 en INPUT. Con el DROP
#           FINAL, cualquier sesion de ruteo IPv6 se caia.
#
#  [FIX-40] *** REPORTE: los puntos de la IP son comodines en regexp ***
#           `message~"10.10.10.1"` tambien matchea 10.10.10.15 y 10.10.10.100.
#
#  [FIX-41] DROPS QUE ROMPEN CLIENTES -> pasan a OPT-, deshabilitados.
#           SQL (6.5), IRC (6.6) y el drop de invalid en forward. Se
#           activan uno por uno tras revisar la lista de deteccion.
#
# ----------------------------------------------------------------------------
#  NUEVO EN v7.10
#
#  [NEW-01] SECCION 6B: DETECCION DE MALWARE Y TV BOX
#           - Sinkholes de Spamhaus/Shadowserver/Europol como DETECCION
#             (no como bloqueo: el sinkhole es la alarma, no el incendio)
#           - Honeypot dark-IP interno: cero falsos positivos
#           - Propagacion IoT (ADB 5555, Telnet, exploits Huawei/Realtek)
#           - DoT hacia resolvers desconocidos (C2 de botnets de TV box)
#           NINGUNA de estas reglas corta trafico.
#
#  [NEW-02] SECCION 9.6: EVG-AUDIT
#           El firewall se revisa a si mismo cada hora y avisa al log
#           cuando algo no cuadra: listas vacias referenciadas con `!`,
#           reglas con `limit` invertido, conntrack al limite, udp-timeout
#           fuera de fabrica, detecciones con demasiadas entradas.
#           Esta es la parte que rompe el ciclo de "cada vez que reviso
#           encuentro otro fallo".
#
#  [NEW-03] SECCION 9.7: EVG-PROXY
#           Deteccion de proxy residencial comparando orig-bytes contra
#           repl-bytes. connection-bytes NO sirve para esto: mide el total
#           de la conexion, no cada sentido -- en campo dio 188 falsos
#           positivos (era la lista de quien veia Netflix).
#
# ----------------------------------------------------------------------------
# FILOSOFIA:  INPUT estricto (protege el router) + FORWARD conservador.
#             Solo se dropea de salida lo que NO tiene caso legitimo
#             residencial. Todo lo demas detecta y reporta.
#
# LIMITES DE CONEXIONES POR ROL:
#   CPE residencial            = 100
#   Router pequeña oficina     = 200
#   *** Borde ISP con BGP      = 500  (este script) ***
#   Core con muchos servicios  = 1000+
# ----------------------------------------------------------------------------
# *** AJUSTAR ANTES DE APLICAR ***
#   1) interface-list WAN y LAN -> YA NO: las puebla la SECCION 9.0 sola.
#      Solo revisar despues de aplicar que hayan quedado bien.
#   2) $EVGWINBOX: DEBE coincidir con el puerto Winbox actual
#   3) Si tu WAN tiene IP privada -> SECCION 2.3 (WAN-PRIVADA)
#   4) SMTP-ALLOWED / SSH-ALLOWED / RDP-ALLOWED / DB-ALLOWED
#   5) CPE-QUARANTINE / CPE-ISOLATED: usar $ADDONCE
#   6) Puertos honeypot: quita 3389 si usas RDP entrante, etc.
#   7) HONEYPOT-INTERNO (2.10): una IP libre por VLAN
#   8) El router debe resolver DNS para la SECCION 9.8: /ip dns print
#   9) EVG-INTERNAS (2.12) -> YA NO: la SECCION 9.0 captura sola los rangos
#      internos que no son RFC1918, incluido el caso 30.30.0.0/16
#      (caso 30.30.0.0/16), declararlo o la deteccion se ensucia
# ----------------------------------------------------------------------------
# APLICACION SEGURA:
#   1) /export file=antes-v714
#   2) Pega el script. Activa el bypass:
#        /ip firewall filter enable [find where comment~"BYPASS"]
#   3) Verifica acceso. EVG-AUTO-OFF-BYPASS lo apaga en 5 min.
#   4) A los 5 MINUTOS:  /log print where message~"EVG-AUDIT"
# ============================================================================

:log warning "EVG-FW2026: INICIO APLICACION (v7.14)"

# ============================================================================
# HELPER: ADDONCE
# ============================================================================
:global ADDONCE do={
  :local ip $1
  :local list $2
  :local cmt $3
  :if ([:len [/ip firewall address-list find where list=$list and address=$ip]] = 0) do={
    /ip firewall address-list add list=$list address=$ip comment=$cmt
  }
}

# ============================================================================
# VARIABLE GLOBAL: PUERTO DE WINBOX
# ============================================================================
:global EVGWINBOX 8291

# ============================================================================
# VARIABLES GLOBALES: UMBRALES DE TRAFICO VALIDO  [NEW-09]
# ============================================================================
#  Todos los umbrales que pueden marcar a un cliente estan aqui, en un solo
#  lugar, con piso y techo. EVG-CALIBRA (SECCION 9.9) los ajusta SOLO a lo
#  que es normal en esta red, siempre dentro de [piso, techo].
#
#  Por que globales: asi el valor "aprendido" sobrevive y las reglas se
#  crean con el mismo numero que luego ajusta el calibrador.
#
#  *** Si preferis fijarlos a mano, poné el valor y listo: EVG-CALIBRA
#      respeta el techo y el piso, y podés desactivar su scheduler. ***

# --- Conexiones concurrentes por cliente en FORWARD (deteccion 6B.5) -------
# Arranca en 800 (un hogar SANO se midio en 224). El calibrador lo lleva a
# 2x el cliente mas ocupado, acotado al rango de abajo. Como el DROP de
# 6B.5 esta deshabilitado, mover este umbral NUNCA corta a nadie: solo
# cambia una lista de deteccion.
:global EVGCONNFLOOD 800
:global EVGCONNFLOORMIN 400
:global EVGCONNFLOORMAX 4000

# --- Conexiones por IP HACIA el router (INPUT 5.1b) ------------------------
# Proteccion del router (borde ISP con BGP = 500). No se autoajusta por
# defecto; cambiar aca si el rol es distinto (core = 1000+).
:global EVGINPUTCONN 500

# --- SYN nuevos por segundo hacia el router (SYN-PROT, SECCION 8) ----------
:global EVGSYN 400

# --- Brute-force ADMIN saliente por cliente (EVG-EGRESS-BF, 6.7) -----------
# Es por SEGUNDO (el /1m es la expiracion del contador). 10/s de conexiones
# nuevas a SSH/Telnet/RDP/VNC ya es claramente brute-force, con FP bajo.
:global EVGEGRESSBF 10

# --- Deteccion de proxy por simetria (EVG-CALIBRA, ex EVG-PROXY) -----------
# minMB : tamaño minimo de cada sentido para considerar el flujo (40 MB, asi
#         una videollamada corta no cuenta).
# factor: se marca si menor*factor > mayor. factor=2 => hay que ser MUY
#         simetrico (ratio > 0.5), como un relay; una descarga es asimetrica.
# minFlows: cuantos flujos grandes y simetricos A LA VEZ. Una videollamada
#         es 1; un proxy relaya varios. Este es el filtro clave contra FP.
:global EVGPROXYMINMB 40
:global EVGPROXYFACTOR 2
:global EVGPROXYMINFLOWS 4

# --- DoT: cuantos clientes distintos vuelven "legitimo" a un resolver -----
:global EVGDOTMINCLIENTES 5

# --- Tope de conexiones para el escaneo del calibrador --------------------
# Si la tabla supera esto, EVG-CALIBRA omite el conteo pesado y solo avisa,
# para no clavar la CPU en una caja muy cargada.
:global EVGCONNMAXSCAN 60000

:local wbactual [/ip service get [find name=winbox] port]
:if ($wbactual != $EVGWINBOX) do={
  :log error "EVG-FW2026: Winbox actual=$wbactual pero el script quiere $EVGWINBOX."
  :log error "EVG-FW2026: si aplicas asi, PIERDES la sesion. Ajusta EVGWINBOX al puerto actual."
  :error "EVG-FW2026: abortado por desalineacion de puerto Winbox."
}

# ============================================================================
# SECCION 0 - LIMPIEZA IDEMPOTENTE  (v4 + v6)
# ============================================================================
/ip firewall filter
:foreach r in=[find where comment~"EVG-FW2026"] do={ remove $r }
:foreach r in=[find where comment~"FW-HARDENED"] do={ remove $r }

/ip firewall raw
:foreach r in=[find where comment~"EVG-FW2026"] do={ remove $r }
:foreach r in=[find where comment~"FW-HARDENED"] do={ remove $r }

/ip firewall address-list
:foreach r in=[find where comment~"EVG-FW2026"] do={ remove $r }
:foreach r in=[find where comment~"FW-HARDENED"] do={ remove $r }

/ipv6 firewall filter
:foreach r in=[find where comment~"EVG-FW2026"] do={ remove $r }
:foreach r in=[find where comment~"FW-HARDENED"] do={ remove $r }

/ipv6 firewall raw
:foreach r in=[find where comment~"EVG-FW2026"] do={ remove $r }
:foreach r in=[find where comment~"FW-HARDENED"] do={ remove $r }

/ipv6 firewall address-list
:foreach r in=[find where comment~"EVG-FW2026"] do={ remove $r }
:foreach r in=[find where comment~"FW-HARDENED"] do={ remove $r }

/system scheduler
:foreach n in={"EVG-POPULATE";"EVG-UPDATE-SPAMHAUS";"EVG-AUTO-OFF-BYPASS";"EVG-QUARANTINE-REPORT";"EVG-AUDIT";"EVG-PROXY";"EVG-CALIBRA";"EVG-AUDIT-EXPOSICION";"EVG-RBL-CHECK";"EVG-DESCUBRE"} do={
  :if ([:len [find name=$n]] > 0) do={ remove [find name=$n] }
}
/system script
:foreach n in={"EVG-POPULATE";"EVG-UPDATE-SPAMHAUS";"EVG-AUTO-OFF-BYPASS";"EVG-QUARANTINE-REPORT";"EVG-AUDIT";"EVG-PROXY";"EVG-CALIBRA";"EVG-AUDIT-EXPOSICION";"EVG-RBL-CHECK";"EVG-DESCUBRE"} do={
  :if ([:len [find name=$n]] > 0) do={ remove [find name=$n] }
}

# ============================================================================
# SECCION 1 - INTERFACE LISTS
# ============================================================================
/interface list
:if ([:len [find name=WAN]] = 0) do={ add name=WAN comment="EVG-FW2026 | Uplinks internet (SOLO fisicas, NO tuneles)" }
:if ([:len [find name=LAN]] = 0) do={ add name=LAN comment="EVG-FW2026 | Interfaces hacia clientes" }

:local nW [:len [/interface list member find where list=WAN]]
:local nL [:len [/interface list member find where list=LAN]]
:if ($nW = 0) do={ :log error "EVG-FW2026: interface-list WAN VACIA. Casi todo el hardening depende de ella." }
:if ($nL = 0) do={ :log error "EVG-FW2026: interface-list LAN VACIA. La deteccion de la SECCION 6B contara CERO. Ver NOTA-LAN." }

# ============================================================================
# SECCION 2 - ADDRESS LISTS
# ============================================================================
/ip firewall address-list

# --- 2.1 RFC1918-ADMIN ------------------------------------------------------
add address=10.0.0.0/8       list=RFC1918-ADMIN comment="EVG-FW2026 | Gestion = LAN RFC1918"
add address=172.16.0.0/12    list=RFC1918-ADMIN comment="EVG-FW2026 | Gestion = LAN RFC1918"
add address=192.168.0.0/16   list=RFC1918-ADMIN comment="EVG-FW2026 | Gestion = LAN RFC1918"

# --- 2.2 BOGONS (sin multicast, para no romper IPTV) ------------------------
add address=0.0.0.0/8         list=BOGONS comment="EVG-FW2026 | This-net"
add address=127.0.0.0/8       list=BOGONS comment="EVG-FW2026 | Loopback"
add address=169.254.0.0/16    list=BOGONS comment="EVG-FW2026 | Link-local"
add address=192.0.2.0/24      list=BOGONS comment="EVG-FW2026 | TEST-NET-1"
add address=198.51.100.0/24   list=BOGONS comment="EVG-FW2026 | TEST-NET-2"
add address=203.0.113.0/24    list=BOGONS comment="EVG-FW2026 | TEST-NET-3"
add address=192.0.0.0/24      list=BOGONS comment="EVG-FW2026 | IETF protocol"
add address=198.18.0.0/15     list=BOGONS comment="EVG-FW2026 | Benchmark"
add address=255.255.255.255   list=BOGONS comment="EVG-FW2026 | Broadcast"

# --- 2.3 WAN-PRIVADA (opcional) ---------------------------------------------
#add address=10.255.0.0/30  list=WAN-PRIVADA comment="EVG-FW2026 | Transito privado upstream"

# --- 2.4 IP-PUBLICA (la puebla EVG-POPULATE) --------------------------------
#add address=X.X.X.X/29  list=IP-PUBLICA comment="EVG-FW2026 | Pool NAT (manual)"

# --- 2.5 RESOLVERS DNS LEGITIMOS  [NEW-01] ---------------------------------
# Para distinguir un cliente con "DNS privado" de Android (normal) de un
# bot hablando DoT con su propio servidor de control (anomalo).
add address=1.1.1.1          list=DNS-OK comment="EVG-FW2026 | Cloudflare"
add address=1.0.0.1          list=DNS-OK comment="EVG-FW2026 | Cloudflare"
add address=8.8.8.8          list=DNS-OK comment="EVG-FW2026 | Google"
add address=8.8.4.4          list=DNS-OK comment="EVG-FW2026 | Google"
add address=9.9.9.9          list=DNS-OK comment="EVG-FW2026 | Quad9"
add address=149.112.112.112  list=DNS-OK comment="EVG-FW2026 | Quad9"
add address=94.140.14.14     list=DNS-OK comment="EVG-FW2026 | AdGuard"
add address=94.140.15.15     list=DNS-OK comment="EVG-FW2026 | AdGuard"
add address=45.90.28.0/24    list=DNS-OK comment="EVG-FW2026 | NextDNS"
add address=45.90.30.0/24    list=DNS-OK comment="EVG-FW2026 | NextDNS"
add address=208.67.222.222   list=DNS-OK comment="EVG-FW2026 | OpenDNS"
add address=208.67.220.220   list=DNS-OK comment="EVG-FW2026 | OpenDNS"
# [FP-02] Ampliada: mas resolvers DoT/DoH conocidos, para no marcar como
# "raro" a un cliente que usa uno legitimo pero que antes no estaba.
add address=1.1.1.2          list=DNS-OK comment="EVG-FW2026 | Cloudflare Malware"
add address=1.0.0.2          list=DNS-OK comment="EVG-FW2026 | Cloudflare Malware"
add address=1.1.1.3          list=DNS-OK comment="EVG-FW2026 | Cloudflare Family"
add address=1.0.0.3          list=DNS-OK comment="EVG-FW2026 | Cloudflare Family"
add address=9.9.9.11         list=DNS-OK comment="EVG-FW2026 | Quad9 ECS"
add address=149.112.112.11   list=DNS-OK comment="EVG-FW2026 | Quad9 ECS"
add address=194.242.2.2      list=DNS-OK comment="EVG-FW2026 | Mullvad"
add address=193.110.81.0/24  list=DNS-OK comment="EVG-FW2026 | dns0.eu"
add address=185.253.5.0/24   list=DNS-OK comment="EVG-FW2026 | dns0.eu"
add address=76.76.2.0/24     list=DNS-OK comment="EVG-FW2026 | ControlD"
add address=76.76.10.0/24    list=DNS-OK comment="EVG-FW2026 | ControlD"
# EVG-CALIBRA (9.9) agrega aqui, con timeout, los resolvers :853 que usan
# muchos clientes de la propia red (consenso = legitimo).

# --- 2.6 SINKHOLES DE INVESTIGACION  *** NO SON PARA BLOQUEAR ***  [NEW-01]
#
# Servidores de Spamhaus, Shadowserver y Europol que se quedaron con los
# dominios de botnets desmanteladas (Andromeda, Avalanche, Nymaim). El
# equipo infectado les habla creyendo que son su C2, y ellos anotan tu IP
# publica -- por eso te llegan los avisos de listado.
#
# *** SE USAN COMO DETECCION, NUNCA COMO BLOQUEO ***
# El sinkhole es la alarma, no el incendio. Bloquearlo no cura la
# infeccion: te deja ciego. Y las listas que circulan traen rangos enteros
# (216.218.185.0/24, 64.190.0.0/16) que son transito de Hurricane Electric
# y hosting real -- bloquear eso tumba trafico legitimo.
#
# Solo IP y prefijos ESPECIFICOS. Nada de /16.
add address=184.105.192.2    list=SINKHOLE comment="EVG-FW2026 | Spamhaus sinkhole (Andromeda)"
add address=216.218.185.162  list=SINKHOLE comment="EVG-FW2026 | Spamhaus/HE sinkhole (Nymaim)"
add address=195.22.26.192/28 list=SINKHOLE comment="EVG-FW2026 | Avalanche sinkhole Europol"
add address=195.22.28.196/30 list=SINKHOLE comment="EVG-FW2026 | Avalanche sinkhole Europol"
add address=199.66.0.7       list=SINKHOLE comment="EVG-FW2026 | FitSec sinkhole (Andromeda)"

# Cuando llegue un aviso nuevo de Spamhaus, agregar la IP EXACTA del
# reporte (no el rango):
#   /ip firewall address-list add list=SINKHOLE address=<ip> \
#       comment="EVG-SINKHOLE-DATA <familia> <fecha>"

# ---------------------------------------------------------------------------
# --- LISTAS DE DATOS PERSISTENTES (NO se borran en la limpieza) ------------
# ---------------------------------------------------------------------------

# --- 2.7 ALLOWLISTS  [FIX-34] ----------------------------------------------
# *** EL PLACEHOLDER 127.0.0.1 ES OBLIGATORIO ***
# En RouterOS, `!LISTA-VACIA` matchea SIEMPRE. En v7.6 estas listas no se
# creaban, asi que la regla 6.5 bloqueaba SQL saliente a TODOS los clientes
# y la 6.7 dejaba a todo el mundo pasando por el detector roto.
# El 127.0.0.1 nunca aparece como origen en forward: solo garantiza que la
# lista EXISTA.
$ADDONCE "127.0.0.1" "SMTP-ALLOWED" "EVG-ALLOWLIST-DATA | placeholder NO BORRAR"
$ADDONCE "127.0.0.1" "SSH-ALLOWED"  "EVG-ALLOWLIST-DATA | placeholder NO BORRAR"
$ADDONCE "127.0.0.1" "RDP-ALLOWED"  "EVG-ALLOWLIST-DATA | placeholder NO BORRAR"
$ADDONCE "127.0.0.1" "DB-ALLOWED"   "EVG-ALLOWLIST-DATA | placeholder NO BORRAR"

# Excepciones reales -- descomentar y ajustar:
#$ADDONCE "10.10.10.10" "SMTP-ALLOWED" "EVG-ALLOWLIST-DATA | Servidor correo legitimo"
#$ADDONCE "10.10.99.5"  "SSH-ALLOWED"  "EVG-ALLOWLIST-DATA | Admin NOC"
#$ADDONCE "10.10.99.10" "RDP-ALLOWED"  "EVG-ALLOWLIST-DATA | Terminal server"
#$ADDONCE "10.10.20.50" "DB-ALLOWED"   "EVG-ALLOWLIST-DATA | Replica MySQL cross-site"

# --- 2.8 CPE-QUARANTINE: SEGUIMIENTO (logging, sin corte) -------------------
$ADDONCE "10.10.10.109" "CPE-QUARANTINE" "EVG-QUARANTINE-DATA | 2026-08-25 malware SMTP"
$ADDONCE "10.10.10.115" "CPE-QUARANTINE" "EVG-QUARANTINE-DATA | 2026-08-25 malware SMTP"
$ADDONCE "10.10.10.125" "CPE-QUARANTINE" "EVG-QUARANTINE-DATA | 2026-08-25 malware SMTP"
$ADDONCE "10.10.20.137" "CPE-QUARANTINE" "EVG-QUARANTINE-DATA | 2026-08-25 malware SMTP"

# --- 2.9 CPE-ISOLATED: CORTE TOTAL (reincidentes cronicos) ------------------
#$ADDONCE "10.10.30.99" "CPE-ISOLATED" "EVG-ISOLATED-DATA | reincidente sin respuesta"

# --- 2.10 HONEYPOT INTERNO (dark-IP)  [NEW-01] -----------------------------
# IP internas que NO existen. Cero falsos positivos: nada legitimo en una
# red residencial busca una direccion que no esta asignada.
# VERIFICAR ANTES que esten fuera del pool y sin lease:
#   /ip pool print
#   /ip dhcp-server lease print where address="10.10.121.250"
#
# *** v7.13 [FIX-43]: esta lista (HONEYPOT-INTERNO) es la MISMA que ahora
#     puebla EVG-DESCUBRE. Antes el autodescubrimiento usaba otro nombre
#     (EVG-HONEYPOT) y la regla 6B.2 no lo veia.
#$ADDONCE "10.10.121.250" "HONEYPOT-INTERNO" "EVG-HONEYPOT-DATA | dark-ip PTO21"
#$ADDONCE "10.10.132.250" "HONEYPOT-INTERNO" "EVG-HONEYPOT-DATA | dark-ip PTO32"

# --- 2.12 RANGOS INTERNOS QUE NO SON RFC1918  [NEW-06] *** AJUSTAR *** -----
#
# Si el ISP usa espacio publico internamente, hay que declararlo o el
# trafico entre sus propias VLAN se cuenta como "hacia internet" y ensucia
# toda la deteccion de la SECCION 6B.
#
# Caso real: INTEDCOL usa 30.30.0.0/16, que NO es privado -- el 30.0.0.0/8
# esta asignado de verdad. Funciona porque hacen NAT, pero para el firewall
# es espacio publico.
#
# Esta lista se UNE a RFC1918-ADMIN en todas las reglas de deteccion.
#add address=30.30.0.0/16    list=EVG-INTERNAS comment="EVG-FW2026 | interno del ISP"
#add address=190.60.52.24/29 list=EVG-INTERNAS comment="EVG-FW2026 | pool propio"
:if ([:len [find where list="EVG-INTERNAS"]] = 0) do={
  add address=127.0.0.1 list=EVG-INTERNAS comment="EVG-FIJO placeholder NO BORRAR"
}

# --- 2.13 PUERTOS DE CENTRO DE CONTROL  [NEW-04] --------------------------
#
#   6969   red entre pares de Hajime. ES LO QUE SPAMHAUS DETECTA y reporta
#          como elf.mirai en el XBL. Mientras siga saliendo, el listado no
#          expira por mas que limpies el equipo.
#   48101  puerto de control de Mirai clasico
#   58455  variante frecuente
#
# OJO: el 6969 tambien es un puerto legitimo de tracker BitTorrent. Por si
# solo tendria falsos positivos; su valor esta en que coincide exactamente
# con lo que Spamhaus reporta.
#
# El 7547 (TR-069) NO se incluye: si el ISP aprovisiona con un ACS remoto,
# bloquearlo le rompe la gestion de TODA la base.

# --- 2.11 GATEWAYS DE FAILOVER  [FIX-42] -----------------------------------
# Los gateways que usa check-gateway=ping quedan EXENTOS de cualquier
# limite de ICMP. Si se les limita la respuesta, la ruta se cae sola.
#
# La puebla EVG-POPULATE leyendo /ip route. Se crea con placeholder para
# que la lista exista desde el primer momento.
$ADDONCE "127.0.0.1" "GATEWAYS" "EVG-GATEWAY-DATA | placeholder NO BORRAR"

# Si algun gateway no lo detecta el script (tuneles, rutas recursivas),
# agregarlo a mano:
#$ADDONCE "200.1.1.1" "GATEWAYS" "EVG-GATEWAY-DATA | gateway WAN1 manual"

# --- 2.14 EVG-NO-AUTOBLOCK: infra que NUNCA se autobloquea  [FP-03] ---------
# El origen de un paquete se falsifica: sin esto, un paquete con src=8.8.8.8
# al puerto 445 mete a tu propio resolver en PORT-SCAN. Esta lista es la
# union de GATEWAYS + BGP-PEERS + DNS-OK + IP-PUBLICA + WAN-PRIVADA, y los
# detectores de INPUT (5.1) NO agregan a estas IP. La puebla EVG-CALIBRA.
# El placeholder garantiza que exista: con la lista VACIA, !EVG-NO-AUTOBLOCK
# matchea TODO, o sea el detector funciona igual que antes (nadie exento).
$ADDONCE "127.0.0.1" "EVG-NO-AUTOBLOCK" "EVG-FIJO placeholder NO BORRAR"

# --- 2.12 BLACKLIST MANUAL -------------------------------------------------
#$ADDONCE "1.2.3.4" "BLACKLIST" "abuso ssh 2026-08"

# ============================================================================
# SECCION 3 - CONNECTION TRACKING  *** NO SE TOCA ***   [FIX-32]
# ============================================================================
#
#  v7.6 hacia:  set udp-timeout=30s udp-stream-timeout=3m
#
#  Combinado con el drop de connection-state=invalid en forward, eso rompe
#  QUIC (HTTP/3: YouTube, Netflix, Meta) y VoIP. El flujo pausa, pierde el
#  estado, y al volver se marca invalid y se dropea.
#
#  v7.10 NO modifica conntrack. Si la caja quedo con los valores de v7.6,
#  restaurar fabrica:
#    /ip firewall connection tracking set udp-timeout=10s \
#        udp-stream-timeout=3m tcp-established-timeout=1d
#
#  Verificar el estado actual (el AUDIT tambien lo revisa cada hora):
#    /ip firewall connection tracking print

:local utActual [/ip firewall connection tracking get udp-timeout]
:if ($utActual > 15s) do={
  :log error ("EVG-FW2026: udp-timeout esta en " . $utActual . " -- valor heredado de v7.6 que ROMPE QUIC. Restaurar: /ip firewall connection tracking set udp-timeout=10s")
}

# ============================================================================
# SECCION 3B - ANTI OPEN-PROXY
# ============================================================================
/ip proxy set enabled=no
/ip socks set enabled=no
/ip upnp set enabled=no

# ============================================================================
# SECCION 4 - RAW
# ============================================================================
/ip firewall raw

add action=accept chain=prerouting disabled=yes comment="EVG-FW2026 | BYPASS-RAW: NO activar salvo emergencia"

# --- 4.0 BLACKLIST MANUAL ---------------------------------------------------
add action=drop chain=prerouting src-address-list=BLACKLIST comment="EVG-FW2026 | Blacklist manual (origen)"
add action=drop chain=prerouting dst-address-list=BLACKLIST comment="EVG-FW2026 | Blacklist manual (destino)"

# --- 4.1 TCP flags imposibles (scans) ---------------------------------------
add action=drop chain=prerouting protocol=tcp tcp-flags=!fin,!syn,!rst,!psh,!ack,!urg comment="EVG-FW2026 | NULL scan"
add action=drop chain=prerouting protocol=tcp tcp-flags=fin,syn comment="EVG-FW2026 | SYN+FIN"
add action=drop chain=prerouting protocol=tcp tcp-flags=fin,rst comment="EVG-FW2026 | FIN+RST"
add action=drop chain=prerouting protocol=tcp tcp-flags=fin,urg,psh comment="EVG-FW2026 | XMAS scan"
add action=drop chain=prerouting protocol=tcp tcp-flags=syn,rst comment="EVG-FW2026 | SYN+RST"

# --- 4.2 Anti-spoofing en WAN -----------------------------------------------
add action=accept chain=prerouting in-interface-list=WAN src-address-list=WAN-PRIVADA comment="EVG-FW2026 | Excepcion: transito con IP privada"
add action=drop chain=prerouting in-interface-list=WAN src-address-list=RFC1918-ADMIN comment="EVG-FW2026 | Anti-spoof: WAN con src privado"
add action=drop chain=prerouting in-interface-list=WAN src-address-list=BOGONS comment="EVG-FW2026 | Anti-spoof: WAN con src bogon"
add action=drop chain=prerouting in-interface-list=WAN src-address-list=IP-PUBLICA comment="EVG-FW2026 | Anti-spoof: WAN con src = mis IPs publicas"

# --- 4.3 Amplificacion UDP pura ---------------------------------------------
add action=drop chain=prerouting in-interface-list=WAN protocol=udp dst-port=19,1900,11211,5353,389 comment="EVG-FW2026 | Amplificacion UDP"
add action=drop chain=prerouting in-interface-list=WAN protocol=tcp dst-port=19 comment="EVG-FW2026 | Chargen TCP"

# --- 4.3b PROTEGER LOS CPE DE EXPLOTACION ENTRANTE  [NEW-04] --------------
#
#  Esto es lo que evita infecciones NUEVAS, y es lo unico que escala: con 16
#  equipos comprometidos de diez fabricantes distintos, la exposicion pesa
#  mas que el modelo del aparato.
#
#  Va en RAW porque es lo mas barato en CPU y porque son puertos que ningun
#  cliente residencial deberia recibir desde internet.
#
#  El 7547 queda FUERA: si el ISP aprovisiona con ACS, lo rompe.
add action=drop chain=prerouting protocol=tcp tcp-flags=syn,!ack in-interface-list=WAN dst-port=23,2323,5555,37215,52869,53413 comment="EVG-FW2026 | Proteger CPE de explotacion entrante"

# --- 4.4 Listas negras entrantes --------------------------------------------
add action=drop chain=prerouting in-interface-list=WAN src-address-list=SPAMHAUS-DROP comment="EVG-FW2026 | Spamhaus DROP entrante"
add action=drop chain=prerouting in-interface-list=WAN dst-address-list=BOGONS comment="EVG-FW2026 | Bogon como destino desde WAN"

# ============================================================================
# SECCION 5 - INPUT  (ESTRICTO)
# ============================================================================
/ip firewall filter

add action=accept chain=input disabled=yes comment="EVG-FW2026 | BYPASS-INPUT: NO activar salvo emergencia"

add action=accept chain=input connection-state=established,related comment="EVG-FW2026 | IN established/related"
add action=drop chain=input connection-state=invalid comment="EVG-FW2026 | IN invalid (seguro: solo trafico al router)"

# --- 5.0 EXCEPCIONES DE CONFIANZA  [FIX-36] --------------------------------
# VAN ANTES DE LOS DETECTORES. En v7.6 iban despues (5.1b), asi que un peer
# BGP o el gateway del upstream que tocara un puerto honeypot quedaba en
# PORT-SCAN 7 dias con la sesion BGP caida.
#
# Y van ACOTADAS por puerto: v7.6 aceptaba TODO TCP desde esas listas, lo
# que dejaba Winbox, SSH y API alcanzables desde el gateway del upstream.
add action=accept chain=input protocol=tcp dst-port=179 src-address-list=BGP-PEERS comment="EVG-FW2026 | BGP peers (exento de detectores)"
add action=accept chain=input protocol=icmp src-address-list=WAN-PRIVADA comment="EVG-FW2026 | ICMP desde transito privado"
add action=accept chain=input protocol=ospf src-address-list=WAN-PRIVADA comment="EVG-FW2026 | OSPF desde transito privado"

# --- 5.1 ANTI-ABUSO ---------------------------------------------------------
add action=drop chain=input src-address-list=PORT-SCAN comment="EVG-FW2026 | Drop port-scanners"

# Detector HONEYPOT: quien toca puertos que nunca ofreces = scanner.
#
# [FIX-37] Timeout bajado de 7d a 1d. RIESGO CONOCIDO: el origen de un
# paquete se falsifica facil. Alguien manda un paquete con origen 8.8.8.8
# al puerto 445 y te autobloqueas Google. Con 1 dia el daño es acotado.
# Si aparece un falso positivo raro, empezar a investigar por aqui:
#   /ip firewall address-list print where list=PORT-SCAN
# [FP-03] src-address-list=!EVG-NO-AUTOBLOCK: la infra propia (gateways,
# peers BGP, resolvers, IP publicas, transito) NO entra a PORT-SCAN aunque
# aparezca como origen -- el origen se falsifica y no queremos autobloquear
# nuestro propio resolver por un paquete spoofeado. Con la lista vacia,
# !EVG-NO-AUTOBLOCK matchea todo (mismo comportamiento que antes).
add action=add-src-to-address-list chain=input protocol=tcp dst-port=21,23,111,135,139,445,1433,3306,5432,5900,6379,9200,11211,27017 in-interface-list=WAN src-address-list=!EVG-NO-AUTOBLOCK address-list=PORT-SCAN address-list-timeout=1d comment="EVG-FW2026 | Detector honeypot TCP"
add action=add-src-to-address-list chain=input protocol=udp dst-port=111,137,161,177,389,520,623,1900,5060,11211 in-interface-list=WAN src-address-list=!EVG-NO-AUTOBLOCK address-list=PORT-SCAN address-list-timeout=1d comment="EVG-FW2026 | Detector honeypot UDP"

# PSD tradicional como backup (scans horizontales verdaderos)
add action=add-src-to-address-list chain=input protocol=tcp psd=40,10s,2,1 in-interface-list=WAN src-address-list=!EVG-NO-AUTOBLOCK address-list=PORT-SCAN address-list-timeout=1d comment="EVG-FW2026 | Detector port-scan PSD (backup)"

# --- 5.1b LIMITE DE CONEXIONES  [FIX-35] -----------------------------------
# El comentario de v7.6 decia 500 pero el valor era 1000. Unificado en 500.
add action=drop chain=input connection-limit="$EVGINPUTCONN,32" in-interface-list=WAN protocol=tcp comment="EVG-FW2026 | Limite conexiones por IP al router (global EVGINPUTCONN)"

# SYN-PROT
add action=jump chain=input connection-state=new protocol=tcp tcp-flags=syn jump-target=SYN-PROT in-interface-list=WAN comment="EVG-FW2026 | Jump SYN-PROT"

# --- 5.2 ANTI OPEN-PROXY ----------------------------------------------------
add action=drop chain=input protocol=tcp dst-port=8080,3128,1080,999 comment="EVG-FW2026 | Anti open-proxy hacia el router"
add action=drop chain=input protocol=udp dst-port=1080 comment="EVG-FW2026 | Anti open-proxy: SOCKS UDP"

# --- 5.3 Acceso administrativo desde LAN RFC1918 ----------------------------
add action=accept chain=input src-address-list=RFC1918-ADMIN comment="EVG-FW2026 | Acceso admin desde LAN/tuneles RFC1918"

# --- 5.4 ICMP  [FIX-42] -- REESCRITO, TUMBABA LA RUTA CON FAILOVER --------
#
# En v7.10 el echo-REPLY estaba limitado a 50/s. Ese es exactamente el
# paquete que espera check-gateway=ping. Con failover + netwatch +
# monitoreo del NOC ese umbral se supera sin ataque, las respuestas que se
# pasan caen al drop de abajo, y la ruta se marca inactiva.
#
# PRINCIPIO: nunca limitar trafico de RESPUESTA. El limite va en lo que
# llega sin invitacion.

# 1) Los gateways de failover: exentos de TODO. Va primero.
add action=accept chain=input protocol=icmp src-address-list=GATEWAYS comment="EVG-FW2026 | ICMP de gateways de failover (SIN limite: check-gateway)"

# 2) ICMP de control: sin limite. Romperlo rompe la red entera.
add action=accept chain=input protocol=icmp icmp-options=3:0-255 comment="EVG-FW2026 | ICMP unreachable (PMTU: OBLIGATORIO)"
add action=accept chain=input protocol=icmp icmp-options=11:0-255 comment="EVG-FW2026 | ICMP time-exceeded (traceroute/PMTU)"

# 3) echo-REPLY: SIN LIMITE. Es respuesta a algo que el router pidio --
#    check-gateway, netwatch, ping de diagnostico.
add action=accept chain=input protocol=icmp icmp-options=0:0 comment="EVG-FW2026 | ICMP echo-reply (SIN limite: lo espera check-gateway)"

# 4) echo-REQUEST entrante: aqui SI tiene sentido limitar, y con 200 no 50.
add action=accept chain=input protocol=icmp icmp-options=8:0 limit=200,200:packet comment="EVG-FW2026 | ICMP echo-request entrante (limitado)"

add action=drop chain=input protocol=icmp comment="EVG-FW2026 | Drop otros ICMP"

# --- 5.5 RUTEO: OSPF + BGP --------------------------------------------------
add action=accept chain=input protocol=ospf comment="EVG-FW2026 | OSPF"
add action=accept chain=input protocol=tcp dst-port=179 src-address-list=BGP-PEERS comment="EVG-FW2026 | BGP desde peers configurados"

# --- 5.5b CIERRE DE GESTION DESDE WAN ---------------------------------------
add action=drop chain=input protocol=tcp dst-port=80,8728,8729 in-interface-list=WAN comment="EVG-FW2026 | WebFig/API fuera de WAN"
add action=drop chain=input protocol=tcp dst-port=135-139,445,1433,3306,5432 in-interface-list=WAN comment="EVG-FW2026 | Puertos peligrosos TCP al router"
add action=drop chain=input protocol=udp dst-port=135-139,445 in-interface-list=WAN comment="EVG-FW2026 | Puertos peligrosos UDP al router"
add action=drop chain=input protocol=udp dst-port=53 in-interface-list=WAN comment="EVG-FW2026 | Drop DNS UDP desde WAN (no open resolver)"
add action=drop chain=input protocol=tcp dst-port=53 in-interface-list=WAN comment="EVG-FW2026 | Drop DNS TCP desde WAN"

# --- 5.6 VPN ENTRANTES (comenta las que NO uses) ----------------------------
# [FIX-44] El accept de PPTP tcp/1723 SE MOVIO a la 5.7c, para que el
# staging de brute-force lo vea. El GRE (datos de PPTP) sigue aqui.
add action=accept chain=input protocol=gre in-interface-list=WAN comment="EVG-FW2026 | GRE (PPTP datos / EoIP)"
add action=accept chain=input protocol=udp dst-port=1701 in-interface-list=WAN comment="EVG-FW2026 | VPN L2TP"
add action=accept chain=input protocol=udp dst-port=500,4500 in-interface-list=WAN comment="EVG-FW2026 | VPN IKE/NAT-T"
add action=accept chain=input protocol=ipsec-esp in-interface-list=WAN comment="EVG-FW2026 | VPN IPsec ESP"
add action=accept chain=input protocol=tcp dst-port=443 in-interface-list=WAN comment="EVG-FW2026 | VPN SSTP"
add action=accept chain=input protocol=tcp dst-port=1194 in-interface-list=WAN comment="EVG-FW2026 | VPN OpenVPN TCP"
add action=accept chain=input protocol=udp dst-port=1194 in-interface-list=WAN comment="EVG-FW2026 | VPN OpenVPN UDP"
add action=accept chain=input protocol=udp dst-port=13231 in-interface-list=WAN comment="EVG-FW2026 | VPN WireGuard"

# --- 5.7 Brute-force SSH desde WAN (staging) --------------------------------
add action=drop chain=input protocol=tcp dst-port=22 src-address-list=BL-SSH comment="EVG-FW2026 | Drop SSH blacklisted"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=SSH-3 address-list=BL-SSH address-list-timeout=1d comment="EVG-FW2026 | SSH 3 -> blacklist 1d"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=SSH-2 address-list=SSH-3 address-list-timeout=1m comment="EVG-FW2026 | SSH 2 -> 3"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=SSH-1 address-list=SSH-2 address-list-timeout=1m comment="EVG-FW2026 | SSH 1 -> 2"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=22 connection-state=new address-list=SSH-1 address-list-timeout=1m comment="EVG-FW2026 | SSH nuevo -> 1"
add action=accept chain=input protocol=tcp dst-port=22 comment="EVG-FW2026 | Aceptar SSH (paso staging)"

# --- 5.7b WINBOX ------------------------------------------------------------
add action=accept chain=input protocol=tcp dst-port=$EVGWINBOX src-address-list=RFC1918-ADMIN comment="EVG-FW2026 | Winbox desde LAN/tuneles (fast-path)"
add action=drop chain=input protocol=tcp dst-port=$EVGWINBOX src-address-list=BL-WINBOX comment="EVG-FW2026 | Drop Winbox blacklisted"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=$EVGWINBOX connection-state=new src-address-list=WB-3 address-list=BL-WINBOX address-list-timeout=1d comment="EVG-FW2026 | Winbox 3 -> blacklist 1d"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=$EVGWINBOX connection-state=new src-address-list=WB-2 address-list=WB-3 address-list-timeout=1m comment="EVG-FW2026 | Winbox 2 -> 3"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=$EVGWINBOX connection-state=new src-address-list=WB-1 address-list=WB-2 address-list-timeout=1m comment="EVG-FW2026 | Winbox 1 -> 2"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=$EVGWINBOX connection-state=new address-list=WB-1 address-list-timeout=1m comment="EVG-FW2026 | Winbox nuevo -> 1"
add action=accept chain=input protocol=tcp dst-port=$EVGWINBOX comment="EVG-FW2026 | Aceptar Winbox (paso staging)"

# --- 5.7c Brute-force PPTP  [FIX-44] ---------------------------------------
# MS-CHAPv2 es criptograficamente debil y el 1723 recibe diccionario
# constante. Si se puede migrar a IKEv2 o WireGuard, hacerlo.
#
# v7.13: este bloque TERMINA con su propio accept. En v7.12 la 5.6 aceptaba
# 1723 antes, asi que estas reglas nunca veian una conexion nueva y el
# baneo no funcionaba. Ahora sigue el mismo patron que SSH y Winbox: el
# drop de baneados y el staging van ARRIBA, el accept al final.
add action=drop chain=input protocol=tcp dst-port=1723 src-address-list=BL-PPTP comment="EVG-FW2026 | Drop PPTP blacklisted"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=1723 connection-state=new src-address-list=PPTP-3 address-list=BL-PPTP address-list-timeout=7d comment="EVG-FW2026 | PPTP 3 -> blacklist 7d"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=1723 connection-state=new src-address-list=PPTP-2 address-list=PPTP-3 address-list-timeout=1m comment="EVG-FW2026 | PPTP 2 -> 3"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=1723 connection-state=new src-address-list=PPTP-1 address-list=PPTP-2 address-list-timeout=1m comment="EVG-FW2026 | PPTP 1 -> 2"
add action=add-src-to-address-list chain=input protocol=tcp dst-port=1723 connection-state=new address-list=PPTP-1 address-list-timeout=1m comment="EVG-FW2026 | PPTP nuevo -> 1"
add action=accept chain=input protocol=tcp dst-port=1723 in-interface-list=WAN comment="EVG-FW2026 | Aceptar PPTP control (paso staging). Comentar si NO usas PPTP."

# --- 5.8 DROP FINAL INPUT desde WAN -----------------------------------------
add action=drop chain=input in-interface-list=WAN comment="EVG-FW2026 | DROP FINAL INPUT desde WAN"

# ============================================================================
# SECCION 6 - FORWARD
# ============================================================================

# --- 6.1 Estado + fasttrack  [FIX-32] --------------------------------------
add action=fasttrack-connection chain=forward connection-state=established,related hw-offload=yes disabled=yes comment="EVG-FW2026 | FastTrack DESACTIVADO (rompe CAKE/QoS y la deteccion de proxy)"
add action=accept chain=forward connection-state=established,related comment="EVG-FW2026 | FWD established/related"

# *** EL DROP DE INVALID EN FORWARD QUEDA DESHABILITADO ***
# Es el principal sospechoso del incidente: con udp-timeout alterado
# rompe QUIC, y en un borde con multiples salidas genera falsos invalid.
# Activar SOLO con conntrack en valores de fabrica y vigilando tickets:
#   /ip firewall filter enable [find comment~"OPT-INVALID"]
add action=drop chain=forward connection-state=invalid disabled=yes comment="EVG-FW2026 | OPT-INVALID (sospechoso del incidente: rompe QUIC)"

# --- 6.2 Spamhaus + Bogon ---------------------------------------------------
add action=drop chain=forward src-address-list=SPAMHAUS-DROP comment="EVG-FW2026 | Spamhaus origen"
add action=drop chain=forward dst-address-list=SPAMHAUS-DROP comment="EVG-FW2026 | Spamhaus destino"
add action=drop chain=forward dst-address-list=BOGONS comment="EVG-FW2026 | Bogon como destino"

# --- 6.3a CPE-ISOLATED: CORTE TOTAL -----------------------------------------
add action=drop chain=forward src-address-list=CPE-ISOLATED out-interface-list=WAN comment="EVG-FW2026 | CPE aislado por reincidencia cronica"

# --- 6.3b CPE-QUARANTINE: SOLO LOGGING (no corta internet) ------------------
add action=log chain=forward src-address-list=CPE-QUARANTINE out-interface-list=WAN protocol=tcp dst-port=25,445,135-139,1433,3306,3389,6660-6669,6697 log-prefix="CPE-MALWARE-ATTEMPT:" comment="EVG-FW2026 | Log intentos abuso CPE en seguimiento"
add action=log chain=forward src-address-list=CPE-QUARANTINE out-interface-list=WAN protocol=udp dst-port=445,137-138 log-prefix="CPE-MALWARE-ATTEMPT:" comment="EVG-FW2026 | Log intentos abuso UDP CPE"
add action=log chain=forward src-address-list=CPE-QUARANTINE dst-address-list=SINKHOLE log-prefix="CPE-MALWARE-C2:" comment="EVG-FW2026 | Log contacto C2 de CPE en seguimiento"

# --- 6.4 SMB / NetBIOS OUTBOUND (aplica a TODOS) ----------------------------
# Gusanos tipo WannaCry. Sin caso legitimo saliente en residencial.
# Si un cliente empresarial comparte carpetas entre sedes SIN tunel, esto
# lo corta -- agregarlo a SSH-ALLOWED... no: crear una excepcion propia.
add action=drop chain=forward protocol=tcp dst-port=445 out-interface-list=WAN comment="EVG-FW2026 | Drop SMB TCP outbound"
add action=drop chain=forward protocol=udp dst-port=445 out-interface-list=WAN comment="EVG-FW2026 | Drop SMB UDP outbound"
add action=drop chain=forward protocol=tcp dst-port=135-139 out-interface-list=WAN comment="EVG-FW2026 | Drop NetBIOS TCP outbound"
add action=drop chain=forward protocol=udp dst-port=137-138 out-interface-list=WAN comment="EVG-FW2026 | Drop NetBIOS UDP outbound"

# --- 6.5 SQL saliente  [FIX-41] -> DETECCION + drop OPCIONAL ---------------
# En v7.6 esto bloqueaba SQL a TODOS los clientes, porque DB-ALLOWED no se
# creaba y `!lista-vacia` matchea siempre. Rompe a empresas y a apps que
# se conectan a su propio servidor.
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=1433,3306,5432 out-interface-list=WAN connection-state=new src-address-list=!DB-ALLOWED address-list=CPE-SQL-SALIENTE address-list-timeout=7d comment="EVG-FW2026 | DETECTA SQL saliente"
add action=drop chain=forward protocol=tcp dst-port=1433,3306,5432 out-interface-list=WAN src-address-list=!DB-ALLOWED disabled=yes comment="EVG-FW2026 | OPT-SQL (revisar CPE-SQL-SALIENTE antes de activar)"

# --- 6.6 IRC saliente  [FIX-41] -> DETECCION + drop OPCIONAL ---------------
# Algunas apps y juegos usan ese rango de puertos.
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=6660-6669,6697 out-interface-list=WAN connection-state=new address-list=CPE-IRC-SALIENTE address-list-timeout=7d comment="EVG-FW2026 | DETECTA IRC saliente"
add action=drop chain=forward protocol=tcp dst-port=6660-6669,6697 out-interface-list=WAN disabled=yes comment="EVG-FW2026 | OPT-IRC (revisar CPE-IRC-SALIENTE antes)"

# --- 6.7 BRUTE-FORCE SALIENTE  [FIX-33 CORREGIDO] --------------------------
#
# v7.6 usaba `limit=20,30:packet`, que matchea MIENTRAS SE ESTA POR DEBAJO
# del umbral y ademas cuenta GLOBAL, no por cliente. Logica invertida: el
# primer SYN de un cliente legitimo lo baneaba, y el que realmente hacia
# brute-force no entraba a la lista.
#
# v7.10 usa dst-limit con mode=src-address: cuenta POR CLIENTE, y el que se
# pasa NO matchea el return, cae a la regla siguiente y SI entra a la lista.
#
# Esta es la deteccion que explica los listados en DroneBL: son los CPE de
# la propia red atacando hacia afuera, no ataques entrantes.
add action=accept chain=forward protocol=tcp dst-port=22,23 out-interface-list=WAN src-address-list=SSH-ALLOWED comment="EVG-FW2026 | SSH/Telnet outbound autorizado"
add action=accept chain=forward protocol=tcp dst-port=3389 out-interface-list=WAN src-address-list=RDP-ALLOWED comment="EVG-FW2026 | RDP outbound autorizado"

add action=drop chain=forward protocol=tcp dst-port=21,22,23,2323,1723,3389,5900 out-interface-list=WAN src-address-list=CPE-BRUTEFORCE comment="EVG-FW2026 | Drop CPE detectado en brute-force saliente"

add action=jump chain=forward jump-target=EVG-EGRESS-BF protocol=tcp dst-port=21,22,23,2323,1723,3389,5900 connection-state=new out-interface-list=WAN comment="EVG-FW2026 | Jump deteccion brute-force saliente"
add action=return chain=EVG-EGRESS-BF dst-limit="$EVGEGRESSBF,$EVGEGRESSBF,src-address/1m" comment="EVG-FW2026 | Bajo umbral por cliente -> normal (global EVGEGRESSBF /s)"
add action=add-src-to-address-list chain=EVG-EGRESS-BF address-list=CPE-BRUTEFORCE address-list-timeout=1d comment="EVG-FW2026 | Sobre umbral -> CPE-BRUTEFORCE"
add action=return chain=EVG-EGRESS-BF comment="EVG-FW2026 | Return a forward"

# --- 6.8 SMTP OUTBOUND ------------------------------------------------------
# Aqui el bloqueo total ES intencional: es lo que saca la IP de PBL y CBL.
# El correo legitimo sale por 587 o 465, que NO se tocan.
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=25 out-interface-list=WAN src-address-list=!SMTP-ALLOWED address-list=SMTP-OUT-ABUSE address-list-timeout=7d comment="EVG-FW2026 | Marca CPE con 25/TCP saliente"
add action=drop chain=forward protocol=tcp dst-port=25 out-interface-list=WAN src-address-list=!SMTP-ALLOWED comment="EVG-FW2026 | Drop 25/TCP saliente no autorizado"

# ============================================================================
# SECCION 6B - DETECCION DE MALWARE Y TV BOX  [NEW-01]
# ============================================================================
#
#  NINGUNA regla de esta seccion corta trafico. Todas registran.
#  Revisar a las 24-48h antes de activar cualquier OPT-.

# --- 6B.1 SINKHOLE: la señal mas confiable que existe ----------------------
#
#  Un equipo que le habla a un sinkhole ESTA infectado. No es heuristica:
#  esos servidores solo reciben trafico de bots.
#
#  NO se bloquea, se REGISTRA. El log te da la IP interna real, asi que
#  dejas de esperar el correo de Spamhaus para saber quien es.
#  Ver la nota en 2.6 sobre por que bloquearlos es contraproducente.
add action=add-src-to-address-list chain=forward dst-address-list=SINKHOLE connection-state=new address-list=CPE-INFECTADO address-list-timeout=30d comment="EVG-FW2026 | SINKHOLE: infeccion CONFIRMADA"
add action=log chain=forward dst-address-list=SINKHOLE connection-state=new log-prefix="SINKHOLE-HIT:" comment="EVG-FW2026 | Log contacto con sinkhole"

# --- 6B.2 HONEYPOT interno (dark-IP): cero falsos positivos ----------------
# [FIX-43] Usa HONEYPOT-INTERNO, la MISMA lista que ahora puebla EVG-DESCUBRE
# (antes el autodescubrimiento escribia en EVG-HONEYPOT y esta regla no lo veia).
add action=add-src-to-address-list chain=forward dst-address-list=HONEYPOT-INTERNO connection-state=new address-list=CPE-INFECTADO address-list-timeout=30d comment="EVG-FW2026 | HONEYPOT: infeccion CONFIRMADA"
add action=drop chain=forward dst-address-list=HONEYPOT-INTERNO comment="EVG-FW2026 | Drop hacia honeypot (el destino no existe)"

# --- 6B.3 Propagacion IoT / TV box ----------------------------------------
#
#  *** tcp-flags=syn,!ack ES OBLIGATORIO ***
#  Los puertos 2323, 53413 y 40860 caen dentro del rango de puertos
#  EFIMEROS (Linux 32768-60999, Windows 49152-65535). Sin el flag se marca
#  el trafico de RETORNO de conexiones legitimas. Verificado en campo:
#  Google (142.251.157.4:443) respondiendo a un cliente que tomo 2323 como
#  puerto de origen.
#
#  23 Telnet | 2323 Telnet alt | 5555 ADB (vector primario de las TV box)
#  37215 exploit Huawei HG532 | 52869 UPnP Realtek | 53413 Netcore/Netis
add action=add-src-to-address-list chain=forward protocol=tcp tcp-flags=syn,!ack dst-port=23,2323,5555,37215,52869,53413 connection-state=new out-interface-list=WAN address-list=CPE-IOT-PROPAGA address-list-timeout=7d comment="EVG-FW2026 | DETECTA propagacion IoT/TVbox"
add action=drop chain=forward protocol=tcp tcp-flags=syn,!ack dst-port=23,2323,5555,37215,52869,53413 out-interface-list=WAN src-address-list=CPE-IOT-PROPAGA disabled=yes comment="EVG-FW2026 | OPT-IOT (revisar CPE-IOT-PROPAGA antes)"

# --- 6B.4 DoT hacia resolvers desconocidos (C2 de botnets de TV box) -------
#
#  Kimwolf, BadBox y familia resuelven su C2 por DNS-over-TLS (853) para no
#  ser vistas. Un cliente con "DNS privado" de Android apuntando a
#  Cloudflare o Google NO cae aqui: la lista DNS-OK lo excluye.
#  Lo que cae es DoT hacia un servidor que nadie conoce. Eso es raro.
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=853 connection-state=new out-interface-list=WAN dst-address-list=!DNS-OK address-list=CPE-DOT-RARO address-list-timeout=7d comment="EVG-FW2026 | DETECTA DoT a resolver desconocido"
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=853 connection-state=new out-interface-list=WAN address-list=CENSO-DOT address-list-timeout=7d comment="EVG-FW2026 | CENSO de clientes que usan DoT"

# El bloqueo, DESHABILITADO. RIESGO: un cliente con DNS privado hacia un
# resolver que no este en DNS-OK se queda SIN resolucion, y el sintoma
# parece falta de servicio. Revisar CENSO-DOT y CPE-DOT-RARO primero.
add action=drop chain=forward protocol=tcp dst-port=853 out-interface-list=WAN dst-address-list=!DNS-OK disabled=yes comment="EVG-FW2026 | OPT-DOT (revisar censo antes de activar)"

# --- 6B.6 CENTRO DE CONTROL MIRAI / HAJIME  [NEW-04] ----------------------
#
#  Esta es la deteccion que resolvio el caso de INTEDCOL: 16 equipos en 26
#  horas, en diez segmentos y con diez fabricantes distintos.
#
#  A diferencia del resto de la SECCION 6B, esta SI bloquea por defecto. La
#  razon: mientras esos SYN sigan saliendo, Spamhaus los ve y el listado en
#  el XBL no expira, asi que los clientes del ISP siguen sin poder entrar a
#  Disney ni a los bancos.
# [FP-01] DOS NIVELES DE CONFIANZA, porque el 6969 tiene doble uso:
#
#   48101 y 58455 son EXCLUSIVOS de Mirai -> infeccion CONFIRMADA.
#   6969 es la firma de Hajime PERO tambien un tracker BitTorrent legitimo.
#        Por si solo -> SOSPECHA (para revisar), NO CONFIRMADO. El drop se
#        mantiene (frena la emision y evita el listado XBL, y romper un
#        tracker BitTorrent es un daño menor), pero no se llama "infectado"
#        a un equipo que quiza solo esta bajando un torrent.
#
#   EVG-CALIBRA escala 6969 a CONFIRMADO solo si el mismo equipo aparece en
#   otra señal dura (sinkhole, honeypot, otro puerto Mirai, propagacion).

# --- Nivel duro: 48101 / 58455 (exclusivos de Mirai) = CONFIRMADO ---
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=48101,58455 connection-state=new out-interface-list=WAN dst-address-list=!EVG-INTERNAS address-list=CPE-MIRAI-C2 address-list-timeout=30d comment="EVG-FW2026 | C2 Mirai (48101/58455): infeccion CONFIRMADA"
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=48101,58455 connection-state=new out-interface-list=WAN dst-address-list=!EVG-INTERNAS address-list=CPE-INFECTADO address-list-timeout=30d comment="EVG-FW2026 | C2 Mirai a lista general"
add action=log chain=forward protocol=tcp dst-port=48101,58455 connection-state=new out-interface-list=WAN dst-address-list=!EVG-INTERNAS log-prefix="MIRAI-C2:" comment="EVG-FW2026 | Log C2 Mirai confirmado"

# --- Nivel sospecha: 6969 (Hajime, pero tambien BitTorrent) = REVISAR ---
add action=add-src-to-address-list chain=forward protocol=tcp dst-port=6969 connection-state=new out-interface-list=WAN dst-address-list=!EVG-INTERNAS address-list=CPE-MIRAI-SOSPECHA address-list-timeout=7d comment="EVG-FW2026 | 6969: Hajime O BitTorrent -> SOSPECHA (revisar, no confirmar)"
add action=log chain=forward protocol=tcp dst-port=6969 connection-state=new out-interface-list=WAN dst-address-list=!EVG-INTERNAS log-prefix="MIRAI-6969:" comment="EVG-FW2026 | Log 6969 (sospecha)"

# --- Drop de la emision (los tres puertos), salvo equipos autorizados ---
add action=drop chain=forward protocol=tcp dst-port=6969,48101,58455 connection-state=new out-interface-list=WAN src-address-list=!SSH-ALLOWED comment="EVG-FW2026 | Drop C2 Mirai/Hajime (6969 puede afectar trackers BitTorrent)"

# --- 6B.7 PROPAGACION LATERAL entre clientes  [NEW-04] --------------------
#
#  El router de borde NUNCA ve esto, porque nunca sale a internet. Y es
#  justo el mecanismo que explica que haya infectados de diez fabricantes
#  distintos: entra por un equipo expuesto y contagia a sus vecinos de la
#  misma subred.
#
#  Requiere que EVG-INTERNAS este poblada si el ISP usa espacio no privado.
add action=add-src-to-address-list chain=forward protocol=tcp tcp-flags=syn,!ack dst-port=23,2323,5555,37215,52869,53413 connection-state=new in-interface-list=LAN dst-address-list=RFC1918-ADMIN address-list=CPE-IOT-LATERAL address-list-timeout=7d comment="EVG-FW2026 | Propagacion LATERAL (RFC1918)"
add action=add-src-to-address-list chain=forward protocol=tcp tcp-flags=syn,!ack dst-port=23,2323,5555,37215,52869,53413 connection-state=new in-interface-list=LAN dst-address-list=EVG-INTERNAS address-list=CPE-IOT-LATERAL address-list-timeout=7d comment="EVG-FW2026 | Propagacion LATERAL (rangos internos)"

# --- 6B.5 Exceso de conexiones ---------------------------------------------
# Umbral 800, deliberadamente alto: en campo se midio un cliente domestico
# SANO con 224 conexiones concurrentes.
# [NEW-09] El umbral (global EVGCONNFLOOD) lo autoajusta EVG-CALIBRA a 2x el
# cliente mas ocupado de esta red. Como el DROP de abajo esta deshabilitado,
# mover el umbral solo cambia una lista de deteccion: nunca corta a nadie.
add action=add-src-to-address-list chain=forward connection-limit="$EVGCONNFLOOD,32" connection-state=new in-interface-list=LAN address-list=CPE-CONNFLOOD address-list-timeout=1d comment="EVG-FW2026 | DETECTA exceso de conexiones (auto: EVGCONNFLOOD)"
add action=drop chain=forward connection-limit="$EVGCONNFLOOD,32" connection-state=new in-interface-list=LAN disabled=yes comment="EVG-FW2026 | OPT-CONEXIONES (auto: EVGCONNFLOOD; revisar CPE-CONNFLOOD antes de activar)"

# ============================================================================
# SECCION 7 - OUTPUT
# ============================================================================
add action=accept chain=output connection-state=established,related comment="EVG-FW2026 | OUT established/related"
add action=drop chain=output connection-state=invalid comment="EVG-FW2026 | OUT invalid"
add action=drop chain=output protocol=tcp dst-port=25 comment="EVG-FW2026 | Router no envia 25/TCP"

# ============================================================================
# SECCION 8 - CHAIN SYN-PROT
# ============================================================================
# El burst debe ser >= rate, o el balde se vacia en el primer instante.
add action=return chain=SYN-PROT connection-state=new protocol=tcp tcp-flags=syn limit="$EVGSYN,$EVGSYN:packet" comment="EVG-FW2026 | SYN bajo limite -> return (global EVGSYN)"
add action=drop chain=SYN-PROT connection-state=new protocol=tcp tcp-flags=syn comment="EVG-FW2026 | SYN sobre limite -> drop"

# ============================================================================
# SECCION 9 - SCRIPTS + SCHEDULERS
# ============================================================================
/system script

# ============================================================================
# --- 9.0 EVG-DESCUBRE: el router se configura solo  [NEW-08]
# ============================================================================
#
#  Deduce del propio equipo lo que hasta ahora se declaraba a mano: cuáles
#  interfaces son WAN, cuáles llevan clientes, y qué espacio considera
#  interno -- incluyendo el público que el ISP use adentro, que era el
#  error que más se repetía.
#
#  *** CORRE ANTES QUE TODO LO DEMAS ***
#  El firewall lee WAN, LAN, EVG-PRIVADAS y EVG-INTERNAS. Si esas listas
#  están vacías cuando se aplican las reglas, pasan dos cosas malas: las
#  reglas con out-interface-list=WAN cuentan cero y parece que la red está
#  limpia, y las que usan `!LISTA` matchean TODO porque en RouterOS una
#  lista vacía negada siempre coincide.
#
#  SOLO PUEBLA LISTAS. No crea ni una regla. Si se equivoca, lo peor que
#  pasa es que una lista quede mal, no que se caiga el servicio.
#
#  Lo que agregues a mano con etiqueta EVG-FIJO no se toca nunca: el
#  descubrimiento solo borra y recalcula lo suyo, marcado EVG-AUTO.
#
#  [FIX-45] Ademas, WAN y LAN solo se reemplazan si la deteccion trajo al
#  menos una interfaz. Si un flap de la ruta por defecto deja la deteccion
#  vacia, se CONSERVA la lista actual en vez de vaciarla y dejar el borde
#  sin firewall hasta el siguiente ciclo.
#
#  Corre cada 30 minutos, así que una VLAN nueva entra sola.
#
#  REVISAR DESPUES DE APLICAR:
#    /log print where message~"EVG-DESCUBRE"
#    /interface list member print where list=WAN
#    /interface list member print where list=LAN
#    /ip firewall address-list print where list=EVG-PRIVADAS
#
add name=EVG-DESCUBRE owner=admin policy=read,write,test source={

:log warning "=== EVG-DESCUBRE: inicio ==="

# ==========================================================================
# PASO 1 · QUÉ INTERFAZ ES WAN
# ==========================================================================
#  Regla: es WAN la interfaz por la que sale una ruta por defecto.
#
#  Se saca del gateway de cada ruta 0.0.0.0/0 y se busca en qué red
#  conectada cae. Eso funciona igual si el tránsito llega con IP pública o
#  con privada, que es el caso de muchos ISP.
#
#  [FIX-45] Se calcula PRIMERO y solo se reemplaza la lista si se detecto
#  algo. Antes se borraba al inicio y un fallo transitorio dejaba WAN vacia.

/interface list
:if ([:len [find name=WAN]] = 0) do={ add name=WAN comment="EVG-FW2026 | Uplinks internet" }
:if ([:len [find name=LAN]] = 0) do={ add name=LAN comment="EVG-FW2026 | Interfaces hacia clientes" }

:local ifsWan [:toarray ""]
:local gws [:toarray ""]

:foreach r in=[/ip route find where dst-address="0.0.0.0/0" and disabled=no] do={
  :do {
    :local gw [:tostr [/ip route get $r gateway]]
    :if ([:typeof [:toip $gw]] = "ip") do={
      :if ([:typeof [:find $gws $gw]] = "nil") do={ :set gws ($gws , $gw) }
      # ¿en qué red conectada cae ese gateway?
      :foreach a in=[/ip address find where disabled=no] do={
        :do {
          :local net [/ip address get $a network]
          :local pfx [/ip address get $a address]
          :local mask [:pick $pfx ([:find $pfx "/"] + 1) [:len $pfx]]
          :if ([:toip $gw] in "$net/$mask") do={
            :local ifn [/ip address get $a interface]
            :if ([:typeof [:find $ifsWan $ifn]] = "nil") do={
              :set ifsWan ($ifsWan , $ifn)
            }
          }
        } on-error={}
      }
    }
  } on-error={}
}

:if ([:len $ifsWan] > 0) do={
  /interface list member remove [find where list="WAN" and comment~"EVG-AUTO"]
  :foreach i in=$ifsWan do={
    :do {
      /interface list member add list="WAN" interface=$i comment="EVG-AUTO transito"
    } on-error={}
  }
  :log warning ("EVG-DESCUBRE: WAN -> " . [:tostr $ifsWan])
} else={
  :log error "EVG-DESCUBRE: NO se detecto ninguna WAN. Se CONSERVA la interface-list WAN actual (no se vacia). Sin ruta por defecto no se puede deducir; declararla a mano si falta."
}

# ==========================================================================
# PASO 2 · QUÉ INTERFACES LLEVAN CLIENTES
# ==========================================================================
#  Regla: tiene IP asignada, no es WAN, no es loopback, y hay señales de
#  vida del otro lado — entradas ARP, leases DHCP o sesiones PPP.
#
#  Lo de las señales de vida importa: evita meter enlaces punto a punto
#  hacia otros routers, que no llevan clientes directamente.
#
#  [FIX-45] "Es WAN" se decide por $ifsWan Y por lo que ya este en la
#  interface-list WAN, para no reclasificar la WAN como LAN si este ciclo
#  no detecto la ruta por defecto.

:local ifsLan [:toarray ""]
:local ifsVacias [:toarray ""]

:foreach a in=[/ip address find where disabled=no] do={
  :do {
    :local ifn [/ip address get $a interface]
    :local pfx [/ip address get $a address]
    :local mask [:pick $pfx ([:find $pfx "/"] + 1) [:len $pfx]]

    :local esWan false
    :foreach w in=$ifsWan do={ :if ($w = $ifn) do={ :set esWan true } }
    :if ([:len [/interface list member find where list="WAN" and interface=$ifn]] > 0) do={ :set esWan true }

    # un /32 es loopback, no lleva clientes
    :local esLoop ($mask = "32")

    :if ((!$esWan) and (!$esLoop)) do={
      :if ([:typeof [:find $ifsLan $ifn]] = "nil") do={
        # ¿hay alguien del otro lado?
        :local vivos [:len [/ip arp find where interface=$ifn]]
        :if ($vivos > 1) do={
          :set ifsLan ($ifsLan , $ifn)
        } else={
          :set ifsVacias ($ifsVacias , $ifn)
        }
      }
    }
  } on-error={}
}

# las VLAN sin IP tambien pueden llevar clientes si estan puenteadas
:foreach v in=[/interface vlan find where disabled=no] do={
  :do {
    :local vn [/interface vlan get $v name]
    :local vp [/interface vlan get $v interface]
    :local sobreWan false
    :foreach w in=$ifsWan do={ :if ($w = $vp) do={ :set sobreWan true } }
    :if ([:len [/interface list member find where list="WAN" and interface=$vp]] > 0) do={ :set sobreWan true }
    :if (!$sobreWan) do={
      :if ([:typeof [:find $ifsLan $vn]] = "nil") do={
        :if ([:len [/ip arp find where interface=$vn]] > 0) do={
          :set ifsLan ($ifsLan , $vn)
        }
      }
    }
  } on-error={}
}

:if ([:len $ifsLan] > 0) do={
  /interface list member remove [find where list="LAN" and comment~"EVG-AUTO"]
  :foreach i in=$ifsLan do={
    :do {
      /interface list member add list="LAN" interface=$i comment="EVG-AUTO clientes"
    } on-error={}
  }
  :log warning ("EVG-DESCUBRE: LAN -> " . [:len $ifsLan] . " interfaces con clientes")
} else={
  :log error "EVG-DESCUBRE: NO se detecto ninguna LAN. Se CONSERVA la interface-list LAN actual. La deteccion lateral no va a medir nada si sigue vacia."
}
:if ([:len $ifsVacias] > 0) do={
  :log info ("EVG-DESCUBRE: sin trafico ARP, omitidas de LAN -> " . [:tostr $ifsVacias])
}

# ==========================================================================
# PASO 3 · QUÉ ESPACIO ES INTERNO
# ==========================================================================
#  Esta es la parte que más se equivocaba a mano.
#
#  Es interno todo lo que este router alcanza SIN pasar por la WAN:
#    a) los RFC1918 y demás rangos reservados
#    b) TODA red conectada del router, incluida la pública que el ISP use
#       adentro (el caso 30.30.0.0/16, que no es privado pero es interno)
#    c) toda ruta estática cuyo gateway sea una IP interna — o sea los
#       bloques que el router entrega a sedes o a clientes downstream
#
#  Sin esto, el tráfico entre las propias VLAN del ISP se cuenta como
#  "hacia internet" y ensucia toda la detección.

/ip firewall address-list remove [find where list="EVG-PRIVADAS" and comment~"EVG-AUTO"]
/ip firewall address-list remove [find where list="EVG-INTERNAS" and comment~"EVG-AUTO"]

# a) reservados. Van a EVG-PRIVADAS y tambien a EVG-INTERNAS, que es la
#    lista que consultan las reglas de deteccion de la SECCION 6B.
:foreach n in={"10.0.0.0/8";"172.16.0.0/12";"192.168.0.0/16";"100.64.0.0/10"; \
               "127.0.0.0/8";"169.254.0.0/16";"224.0.0.0/4"} do={
  :do {
    /ip firewall address-list add list="EVG-PRIVADAS" address=$n comment="EVG-AUTO reservado"
  } on-error={}
  :do {
    /ip firewall address-list add list="EVG-INTERNAS" address=$n comment="EVG-AUTO reservado"
  } on-error={}
}

# b) redes conectadas del router
:local nConn 0
:foreach a in=[/ip address find where disabled=no] do={
  :do {
    :local pfx [/ip address get $a address]
    :local net [/ip address get $a network]
    :local mask [:pick $pfx ([:find $pfx "/"] + 1) [:len $pfx]]
    :if ($mask != "32") do={
      :local red "$net/$mask"
      :if ([:len [/ip firewall address-list find where list="EVG-PRIVADAS" and address=$red]] = 0) do={
        /ip firewall address-list add list="EVG-PRIVADAS" address=$red \
          comment="EVG-AUTO red conectada"
        :do {
          /ip firewall address-list add list="EVG-INTERNAS" address=$red \
            comment="EVG-AUTO red conectada"
        } on-error={}
        :set nConn ($nConn + 1)
      }
    }
  } on-error={}
}

# c) rutas estáticas hacia adentro
:local nRut 0
:foreach r in=[/ip route find where static=yes and disabled=no] do={
  :do {
    :local dst [:tostr [/ip route get $r dst-address]]
    :local gw  [:tostr [/ip route get $r gateway]]
    :if (($dst != "0.0.0.0/0") and ([:typeof [:toip $gw]] = "ip")) do={
      # el gateway tiene que caer en una red conectada que NO sea WAN
      :local interna false
      :foreach a in=[/ip address find where disabled=no] do={
        :do {
          :local ifn [/ip address get $a interface]
          :local esWan false
          :foreach w in=$ifsWan do={ :if ($w = $ifn) do={ :set esWan true } }
          :if ([:len [/interface list member find where list="WAN" and interface=$ifn]] > 0) do={ :set esWan true }
          :if (!$esWan) do={
            :local net [/ip address get $a network]
            :local pfx [/ip address get $a address]
            :local mask [:pick $pfx ([:find $pfx "/"] + 1) [:len $pfx]]
            :if ([:toip $gw] in "$net/$mask") do={ :set interna true }
          }
        } on-error={}
      }
      :if ($interna) do={
        :if ([:len [/ip firewall address-list find where list="EVG-PRIVADAS" and address=$dst]] = 0) do={
          /ip firewall address-list add list="EVG-PRIVADAS" address=$dst \
            comment="EVG-AUTO ruta interna"
          :do {
            /ip firewall address-list add list="EVG-INTERNAS" address=$dst \
              comment="EVG-AUTO ruta interna"
          } on-error={}
          :set nRut ($nRut + 1)
        }
      }
    }
  } on-error={}
}

:log warning ("EVG-DESCUBRE: PRIVADAS -> 7 reservados + " . $nConn . " conectadas + " . \
  $nRut . " rutas internas")

# ==========================================================================
# PASO 4 · LAS PÚBLICAS DE SALIDA
# ==========================================================================
#  De dos fuentes, porque con NAT por address-list las públicas de salida
#  pueden no estar asignadas al router.

/ip firewall address-list remove [find where list="IP-PUBLICA" and comment~"EVG-AUTO"]
:local nPub 0

:foreach a in=[/ip address find where disabled=no] do={
  :do {
    :local adr [/ip address get $a address]
    :local net [/ip address get $a network]
    :local priv false
    :if ($net in 10.0.0.0/8)     do={ :set priv true }
    :if ($net in 172.16.0.0/12)  do={ :set priv true }
    :if ($net in 192.168.0.0/16) do={ :set priv true }
    :if ($net in 127.0.0.0/8)    do={ :set priv true }
    :if ($net in 169.254.0.0/16) do={ :set priv true }
    :if ($net in 100.64.0.0/10)  do={ :set priv true }
    :if ($net in 224.0.0.0/4)    do={ :set priv true }
    :if (!$priv) do={
      :local host [:pick $adr 0 [:find $adr "/"]]
      :if ([:len [/ip firewall address-list find where list="IP-PUBLICA" and address=$host]] = 0) do={
        /ip firewall address-list add list="IP-PUBLICA" address=$host comment="EVG-AUTO publica del router"
        :set nPub ($nPub + 1)
      }
    }
  } on-error={}
}

:foreach n in=[/ip firewall nat find where chain="srcnat" and action="src-nat" and disabled=no] do={
  :do {
    :local ta [:tostr [/ip firewall nat get $n to-addresses]]
    :if (([:len $ta] > 6) and ([:typeof [:find $ta "-"]] = "nil")) do={
      :if ([:len [/ip firewall address-list find where list="IP-PUBLICA" and address=$ta]] = 0) do={
        /ip firewall address-list add list="IP-PUBLICA" address=$ta comment="EVG-AUTO publica de salida NAT"
        :set nPub ($nPub + 1)
      }
    }
  } on-error={}
}
:log warning ("EVG-DESCUBRE: IP-PUBLICA -> " . $nPub)

# ==========================================================================
# PASO 5 · GATEWAYS DE FAILOVER
# ==========================================================================
#  Van exentos de cualquier límite de ICMP. Limitar el echo-reply hace que
#  check-gateway los dé por caídos y la ruta se cae sola.

/ip firewall address-list remove [find where list="GATEWAYS" and comment~"EVG-AUTO"]
:local nGw 0
:foreach r in=[/ip route find where !(gateway="")] do={
  :do {
    :local gw [:tostr [/ip route get $r gateway]]
    :if ([:typeof [:toip $gw]] = "ip") do={
      :if ([:len [/ip firewall address-list find where list="GATEWAYS" and address=$gw]] = 0) do={
        /ip firewall address-list add list="GATEWAYS" address=$gw comment="EVG-AUTO gateway"
        :set nGw ($nGw + 1)
      }
    }
  } on-error={}
}
:log warning ("EVG-DESCUBRE: GATEWAYS -> " . $nGw)

# ==========================================================================
# PASO 6 · PEERS BGP
# ==========================================================================
/ip firewall address-list remove [find where list="BGP-PEERS" and comment~"EVG-AUTO"]
:local nBgp 0
:do {
  :foreach c in=[/routing bgp connection find] do={
    :do {
      :local ra [:tostr [/routing bgp connection get $c remote.address]]
      :if ([:len $ra] > 0) do={
        :if ([:typeof [:toip $ra]] = "ip") do={
          /ip firewall address-list add list="BGP-PEERS" address=$ra comment="EVG-AUTO peer BGP"
          :set nBgp ($nBgp + 1)
        } else={
          :do { /ipv6 firewall address-list add list="V6-BGP-PEERS" address=$ra comment="EVG-AUTO peer BGP" } on-error={}
        }
      }
    } on-error={}
  }
} on-error={}
:if ($nBgp > 0) do={ :log warning ("EVG-DESCUBRE: BGP-PEERS -> " . $nBgp) }


# ==========================================================================
# PASO 7B · ELEGIR LAS IP DE HONEYPOT
# ==========================================================================
#  La trampa mas simple que existe: una direccion que NO existe dentro de
#  cada VLAN de clientes. Un equipo sano nunca la busca. El que la toca,
#  esta infectado -- sin umbrales, sin heuristica.
#
#  Y detecta el escaneo ENTRE vecinos, que nunca sale a internet y que el
#  router de borde no ve por ningun otro medio.
#
#  [FIX-43] Se puebla la lista HONEYPOT-INTERNO -- la MISMA que matchea la
#  regla 6B.2. En v7.12 se escribia en EVG-HONEYPOT y la regla no lo veia,
#  asi que las dark-IP autodescubiertas no detectaban nada.
#
#  COMO SE ELIGE
#    Tiene que estar DENTRO del rango de esa VLAN, porque el bot escanea su
#    propia subred. Se prueba desde la ultima direccion utilizable hacia
#    abajo, y se toma la primera que cumpla las tres condiciones:
#      1. fuera de todo pool DHCP
#      2. sin entrada ARP (nadie la esta usando)
#      3. sin lease DHCP registrado
#
#  RIESGO QUE SE EVITA
#    Si se eligiera una que el DHCP entrega despues, ese cliente quedaria
#    marcado como infectado sin serlo -- y ahi se pierde lo unico que hace
#    valiosa esta deteccion, que es no tener falsos positivos.

/ip firewall address-list remove [find where list="HONEYPOT-INTERNO" and comment~"EVG-AUTO"]

:local nHp 0
:local sinHp [:toarray ""]

:foreach ifn in=$ifsLan do={
  :do {
    # buscar la red de esa interfaz
    :foreach a in=[/ip address find where interface=$ifn and disabled=no] do={
      :do {
        :local pfx [/ip address get $a address]
        :local net [/ip address get $a network]
        :local mask [:tonum [:pick $pfx ([:find $pfx "/"] + 1) [:len $pfx]]]

        # solo /22 a /29: mas grande es raro, mas chico no deja lugar
        :if (($mask >= 22) and ($mask <= 29)) do={
          :local base [:tostr $net]
          :local p1 [:find $base "." 0]
          :local p2 [:find $base "." ($p1 + 1)]
          :local p3 [:find $base "." ($p2 + 1)]
          :local pre [:pick $base 0 $p3]
          :local o4 [:tonum [:pick $base ($p3 + 1) [:len $base]]]

          # cuantas direcciones tiene la subred
          :local total (1 << (32 - $mask))
          # el ultimo octeto de la broadcast, si la subred cabe en un /24
          :local ultimo 254
          :if ($mask >= 24) do={ :set ultimo ($o4 + $total - 2) }

          :local elegida ""
          :local intentos 0

          # probar desde la ultima utilizable hacia abajo
          :while ((([:len $elegida] = 0) and ($intentos < 12))) do={
            :local cand ($pre . "." . ($ultimo - $intentos))
            :local libre true

            # 1. fuera de todo pool
            :foreach pl in=[/ip pool find] do={
              :do {
                :local rg [:tostr [/ip pool get $pl ranges]]
                :if ([:typeof [:find $rg ($pre . ".")]] != "nil") do={
                  # el pool toca esta subred: comparar el ultimo octeto
                  :local gui [:find $rg "-"]
                  :if ([:typeof $gui] = "num") do={
                    :local hasta [:pick $rg ($gui + 1) [:len $rg]]
                    :local h4 [:tonum [:pick $hasta ([:find $hasta "." ([:find $hasta "." ([:find $hasta "." 0] + 1)] + 1)] + 1) [:len $hasta]]]
                    :if (($ultimo - $intentos) <= $h4) do={ :set libre false }
                  }
                }
              } on-error={}
            }

            # 2. sin ARP
            :if ($libre) do={
              :if ([:len [/ip arp find where address=$cand]] > 0) do={ :set libre false }
            }

            # 3. sin lease DHCP
            :if ($libre) do={
              :do {
                :if ([:len [/ip dhcp-server lease find where address=$cand]] > 0) do={ :set libre false }
              } on-error={}
            }

            # 4. que no sea la IP del propio router
            :if ($libre) do={
              :if ([:len [/ip address find where address~$cand]] > 0) do={ :set libre false }
            }

            :if ($libre) do={ :set elegida $cand }
            :set intentos ($intentos + 1)
          }

          :if ([:len $elegida] > 0) do={
            :do {
              /ip firewall address-list add list="HONEYPOT-INTERNO" address=$elegida \
                comment=("EVG-AUTO dark-ip " . $ifn)
              :set nHp ($nHp + 1)
              :log info ("EVG-DESCUBRE: honeypot " . $elegida . " para " . $ifn)
            } on-error={}
          } else={
            :set sinHp ($sinHp , $ifn)
          }
        }
      } on-error={}
    }
  } on-error={}
}

:log warning ("EVG-DESCUBRE: HONEYPOT -> " . $nHp . " dark-IP elegidas y verificadas")
:if ([:len $sinHp] > 0) do={
  :log warning ("EVG-DESCUBRE: sin lugar libre para honeypot en -> " . [:tostr $sinHp] . \
    ". Revisar el pool: si ocupa toda la subred, hay que dejar una IP fuera o declararla a mano con EVG-FIJO.")
}

# ==========================================================================
# PASO 7 · LISTAS QUE DEBEN EXISTIR AUNQUE ESTÉN VACÍAS
# ==========================================================================
#  En RouterOS `!LISTA-VACIA` matchea SIEMPRE. Una lista de excepciones que
#  no existe convierte su regla en un bloqueo universal. Ese bug ya cortó
#  SQL y RDP a todos los clientes de un ISP.

:foreach L in={"SMTP-ALLOWED";"SSH-ALLOWED";"RDP-ALLOWED";"DB-ALLOWED"; \
               "EVG-EXENTOS";"HONEYPOT-INTERNO";"EVG-INTERNAS"; \
               "EVG-NO-AUTOBLOCK"} do={
  :if ([:len [/ip firewall address-list find where list=$L]] = 0) do={
    :do {
      /ip firewall address-list add list=$L address=127.0.0.1 \
        comment="EVG-FIJO placeholder NO BORRAR"
    } on-error={}
  }
}

# ==========================================================================
# RESUMEN
# ==========================================================================
:local rWan [:len [/interface list member find where list="WAN"]]
:local rLan [:len [/interface list member find where list="LAN"]]
:local rPri [:len [/ip firewall address-list find where list="EVG-PRIVADAS"]]
:local rPub [:len [/ip firewall address-list find where list="IP-PUBLICA"]]
:local rHp  [:len [/ip firewall address-list find where list="HONEYPOT-INTERNO"]]

:log warning ("EVG-DESCUBRE: WAN=" . $rWan . " LAN=" . $rLan . " PRIVADAS=" . $rPri . \
  " PUBLICAS=" . $rPub)

:if ($rHp <= 1) do={
  :log warning "EVG-DESCUBRE: no se pudo elegir ninguna dark-IP de honeypot. Revisar que los pools DHCP dejen al menos una direccion libre por subred, o declararlas a mano con etiqueta EVG-FIJO."
}
:log warning "=== EVG-DESCUBRE: fin ==="
}
# --- 9.1 AUTO-POBLADO -------------------------------------------------------
add name=EVG-POPULATE owner=admin policy=read,write,test source={
:log info "EVG-POPULATE: inicio"
:if ([/ip proxy get enabled]) do={ /ip proxy set enabled=no; :log warning "EVG-POPULATE: web-proxy estaba HABILITADO, apagado (posible compromiso)" }
:if ([/ip socks get enabled]) do={ /ip socks set enabled=no; :log warning "EVG-POPULATE: SOCKS estaba HABILITADO, apagado (posible compromiso)" }
:if ([/ip upnp get enabled]) do={ /ip upnp set enabled=no; :log warning "EVG-POPULATE: UPnP estaba HABILITADO, apagado" }
/ip firewall address-list remove [find where list="IP-PUBLICA" and comment~"EVG-AUTO"]
:local pubc 0
:foreach a in=[/ip address find where disabled=no] do={
  :local adr [/ip address get $a address]
  :local net [/ip address get $a network]
  :local priv false
  :if ($net in 10.0.0.0/8)     do={ :set priv true }
  :if ($net in 172.16.0.0/12)  do={ :set priv true }
  :if ($net in 192.168.0.0/16) do={ :set priv true }
  :if ($net in 127.0.0.0/8)    do={ :set priv true }
  :if ($net in 169.254.0.0/16) do={ :set priv true }
  :if ($net in 100.64.0.0/10)  do={ :set priv true }
  :if ($net in 224.0.0.0/4)    do={ :set priv true }
  :if (!$priv) do={
    :local slash [:find $adr "/"]
    :local host [:pick $adr 0 $slash]
    :do { /ip firewall address-list add list="IP-PUBLICA" address=$host comment="EVG-AUTO IP del router" } on-error={}
    :set pubc ($pubc + 1)
  }
}
/ip firewall address-list remove [find where list="BGP-PEERS" and comment~"EVG-AUTO"]
:do { /ipv6 firewall address-list remove [find where list="V6-BGP-PEERS" and comment~"EVG-AUTO"] } on-error={}
:local bgpc 0
:local bgpc6 0
:do {
  :foreach c in=[/routing bgp connection find] do={
    :do {
      :local ra [/routing bgp connection get $c remote.address]
      :if ([:typeof $ra] != "nothing" && [:len $ra] > 0) do={
        :if ([:typeof [:toip $ra]] = "ip") do={
          :do { /ip firewall address-list add list="BGP-PEERS" address=$ra comment="EVG-AUTO peer BGP" } on-error={}
          :set bgpc ($bgpc + 1)
        } else={
          :do { /ipv6 firewall address-list add list="V6-BGP-PEERS" address=$ra comment="EVG-AUTO peer BGP v6" } on-error={}
          :set bgpc6 ($bgpc6 + 1)
        }
      }
    } on-error={}
  }
} on-error={ :log info "EVG-POPULATE: sin BGP" }
# --- GATEWAYS de failover  [FIX-42] ---
# Lee /ip route y saca los gateways. Si se les limita el ICMP de respuesta,
# check-gateway los da por caidos y la ruta se marca inactiva.
/ip firewall address-list remove [find where list="GATEWAYS" and comment~"EVG-AUTO"]
:local gwc 0
:do {
  :foreach rt in=[/ip route find where !(gateway="")] do={
    :do {
      :local gw [/ip route get $rt gateway]
      :if ([:typeof [:toip $gw]] = "ip") do={
        :if ([:len [/ip firewall address-list find where list="GATEWAYS" and address=$gw]] = 0) do={
          /ip firewall address-list add list="GATEWAYS" address=$gw comment="EVG-AUTO gateway de ruta"
          :set gwc ($gwc + 1)
        }
      }
    } on-error={}
  }
} on-error={}
:if ($gwc = 0) do={
  :log warning "EVG-POPULATE: no se detecto ningun gateway por IP. Si usas check-gateway, agregalos a mano a la lista GATEWAYS o la ruta se puede caer."
}
:log warning ("EVG-POPULATE OK | IP-PUBLICA=" . $pubc . " | BGP-PEERS=" . $bgpc . " | V6-BGP=" . $bgpc6 . " | GATEWAYS=" . $gwc)
}

# --- 9.2 Spamhaus DROP  [FIX-38] con validacion de cordura -----------------
# Si el fetch trae un archivo parcial o el formato cambia, se pueden cargar
# rangos equivocados y bloquear destinos legitimos sin que nadie se entere.
# Ahora valida que el conteo este en un rango razonable ANTES de reemplazar
# la lista buena.
#
# OJO 2026: Spamhaus esta migrando el formato DROP de texto plano a JSON.
# Si drop.txt deja de responder o devuelve HTML, este script CONSERVA la
# lista previa (no la vacia) y lo registra. Migrar el parser a
# https://www.spamhaus.org/drop/drop_v4.json cuando haga falta.
add name=EVG-UPDATE-SPAMHAUS owner=admin policy=read,write,test source={
:local MAIN "SPAMHAUS-DROP"
:local TMP  "SPAMHAUS-DROP-TMP"
:local URL  "https://www.spamhaus.org/drop/drop.txt"
:local F    "evg_spamhaus.txt"
:local MINOK 300
:local MAXOK 5000
:local CNT 0
:log info "EVG-SPAMHAUS: inicio"
/ip firewall address-list remove [find list=$TMP]
:if ([:len [/file find name=$F]] > 0) do={ /file remove [find name=$F] }
:do { /tool fetch url=$URL dst-path=$F check-certificate=yes } on-error={ :log warning "EVG-SPAMHAUS: fallo fetch" }
:if ([:len [/file find name=$F]] > 0) do={
  :local TXT [/file get $F contents]
  :if ([:pick $TXT 0 1] != "<") do={
    :local P 0
    :local L [:len $TXT]
    :while ($P < $L) do={
      :local N [:find $TXT "\n" $P]
      :if ($N = -1) do={ :set N $L }
      :local LINE [:pick $TXT $P $N]
      :set P ($N + 1)
      :local LL [:len $LINE]
      :if ($LL > 0) do={ :if ([:pick $LINE ($LL-1) $LL] = "\r") do={ :set LINE [:pick $LINE 0 ($LL-1)] } }
      :if (([:len $LINE] > 0) && ([:pick $LINE 0 1] != "#") && ([:pick $LINE 0 1] != ";")) do={
        :local SEMI [:find $LINE ";" 0]
        :local PART $LINE
        :if ($SEMI != -1) do={ :set PART [:pick $LINE 0 $SEMI] }
        :while (([:len $PART] > 0) && ([:pick $PART 0 1] = " ")) do={ :set PART [:pick $PART 1 [:len $PART]] }
        :local SP [:find $PART " " 0]
        :if ($SP != -1) do={ :set PART [:pick $PART 0 $SP] }
        :if (([:len $PART] >= 7) && ([:find $PART "/" 0] != -1) && ($PART ~ "^[0-9]")) do={
          :do { /ip firewall address-list add list=$TMP address=$PART comment="EVG-SPAMHAUS-DATA" } on-error={}
          :set CNT ($CNT + 1)
        }
      }
    }
  } else={ :log warning "EVG-SPAMHAUS: respuesta HTML, abortado" }
}
# --- VALIDACION DE CORDURA [FIX-38] ---
:if (($CNT >= $MINOK) and ($CNT <= $MAXOK)) do={
  /ip firewall address-list remove [find list=$MAIN]
  :foreach id in=[/ip firewall address-list find list=$TMP] do={ /ip firewall address-list set $id list=$MAIN }
  :log info ("EVG-SPAMHAUS: OK total=" . $CNT)
} else={
  /ip firewall address-list remove [find list=$TMP]
  :if ($CNT = 0) do={
    :log warning "EVG-SPAMHAUS: sin datos, se conservo la lista previa"
  } else={
    :log error ("EVG-SPAMHAUS: conteo ANOMALO (" . $CNT . ", esperado entre " . $MINOK . " y " . $MAXOK . "). Se conservo la lista previa para no bloquear destinos legitimos.")
  }
}
:if ([:len [/file find name=$F]] > 0) do={ /file remove [find name=$F] }
}

# --- 9.3 Auto-off bypass ----------------------------------------------------
add name=EVG-AUTO-OFF-BYPASS owner=admin policy=read,write,test source={
:foreach r in=[/ip firewall filter find where comment~"BYPASS"] do={ /ip firewall filter set $r disabled=yes }
:foreach r in=[/ip firewall raw find where comment~"BYPASS"] do={ /ip firewall raw set $r disabled=yes }
:foreach r in=[/ipv6 firewall filter find where comment~"BYPASS"] do={ /ipv6 firewall filter set $r disabled=yes }
:log warning "EVG-FW2026: BYPASS apagado automaticamente"
}

# --- 9.4 REPORTE DIARIO  [FIX-40] ------------------------------------------
# Los puntos de la IP se escapan: en regexp el punto es comodin, asi que
# 10.10.10.1 tambien matcheaba 10.10.10.15, 10.10.10.100, etc.
add name=EVG-QUARANTINE-REPORT owner=admin policy=read,write,test source={
:log warning "=== EVG REPORTE DIARIO ==="
:local total 0
:foreach cpe in=[/ip firewall address-list find where list=CPE-QUARANTINE] do={
  :local ip [/ip firewall address-list get $cpe address]
  :local pat ""
  :for i from=0 to=([:len $ip] - 1) do={
    :local c [:pick $ip $i ($i + 1)]
    :if ($c = ".") do={ :set pat ($pat . "\\.") } else={ :set pat ($pat . $c) }
  }
  :local hits 0
  :foreach l in=[/log find where message~"CPE-MALWARE" and message~$pat] do={ :set hits ($hits + 1) }
  :if ($hits > 0) do={
    :log warning ("EVG-REPORTE: " . $ip . " -> " . $hits . " intentos de abuso 24h")
    :set total ($total + 1)
  } else={
    :log info ("EVG-REPORTE: " . $ip . " -> SIN actividad (candidato a retirar)")
  }
}
:local a [:len [/ip firewall address-list find where list=CPE-INFECTADO]]
:local b [:len [/ip firewall address-list find where list=CPE-IOT-PROPAGA]]
:local c [:len [/ip firewall address-list find where list=CPE-BRUTEFORCE]]
:local d [:len [/ip firewall address-list find where list=CPE-PROXY]]
:local e [:len [/ip firewall address-list find where list=CPE-DOT-RARO]]
:local f [:len [/ip firewall address-list find where list=SMTP-OUT-ABUSE]]
:local g [:len [/ip firewall address-list find where list=CPE-CONNFLOOD]]
:local h [:len [/ip firewall address-list find where list=CENSO-DOT]]
:local i [:len [/ip firewall address-list find where list=CPE-MIRAI-C2]]
:local j [:len [/ip firewall address-list find where list=CPE-IOT-LATERAL]]
:local k [:len [/ip firewall address-list find where list=CPE-MIRAI-SOSPECHA]]
:log warning ("EVG-REPORTE CONFIRMADOS (sinkhole/honeypot/C2): " . $a . "  <-- NO es heuristica, estan infectados")
:log warning ("EVG-REPORTE | C2 Mirai(confirmado)=" . $i . " | 6969 SOSPECHA(revisar, puede ser BitTorrent)=" . $k . " | propagacion lateral=" . $j)
:log warning ("EVG-REPORTE | IoT=" . $b . " bruteforce=" . $c . " proxy=" . $d . " DoT-raro=" . $e)
:log warning ("EVG-REPORTE | SMTP=" . $f . " conexiones=" . $g . " censo-DoT=" . $h)
:log warning ("=== FIN | CPE en seguimiento activos hoy=" . $total . " ===")
:if ($a > 0) do={
  :log error "EVG-FW2026: hay equipos CONFIRMADOS infectados -> /ip firewall address-list print where list=CPE-INFECTADO"
}
}

# ============================================================================
# --- 9.9 EVG-CALIBRA: autocalibracion + deteccion por simetria  [NEW-09]
# ============================================================================
#  Reemplaza al viejo EVG-PROXY. En UNA sola pasada por la tabla de
#  conexiones hace cuatro cosas, y ademas dos que no necesitan escanear:
#
#   1. UMBRAL DE CONEXIONES (6B.5): mide el cliente mas ocupado y fija el
#      umbral en 2x eso, acotado a [EVGCONNFLOORMIN, EVGCONNFLOORMAX], con
#      histeresis del 15% para no oscilar. Lee el valor ACTUAL de la regla
#      (que persiste en config), asi sobrevive a un reboot. Como el DROP de
#      6B.5 esta deshabilitado, esto solo cambia una lista de deteccion:
#      NUNCA corta a un cliente.
#
#   2. PROXY POR SIMETRIA [FP-04]: cuenta, POR EQUIPO, cuantos flujos TCP
#      grandes (> EVGPROXYMINMB cada sentido) y simetricos (menor*factor >
#      mayor) hay a la vez. Una videollamada es 1 flujo -> no se marca. Un
#      proxy relaya varios -> a CPE-PROXY solo con >= EVGPROXYMINFLOWS.
#      (connection-bytes/rate no sirven: miden el total, no cada sentido.
#      Requiere FastTrack desactivado para ver los bytes reales.)
#
#   3. DoT POR CONSENSO [FP-02]: cuenta clientes DISTINTOS por destino :853.
#      Un C2 lo usa un bot; un resolver legitimo lo usan muchos. El destino
#      con >= EVGDOTMINCLIENTES clientes pasa a DNS-OK (con timeout) y deja
#      de caer en CPE-DOT-RARO.
#      OJO: en una red MUY chica subir EVGDOTMINCLIENTES; 5 bots compartiendo
#      un C2 podrian colarse. El bloqueo OPT-DOT esta apagado, asi que el
#      unico efecto es sobre una lista de deteccion.
#
#   4. INFRA DE CONFIANZA [FP-03]: arma EVG-NO-AUTOBLOCK con la union de
#      GATEWAYS + BGP-PEERS + DNS-OK + IP-PUBLICA + WAN-PRIVADA.
#
#   5. CORROBORACION 6969 [FP-01]: un equipo en CPE-MIRAI-SOSPECHA que
#      tambien aparezca en una señal DURA (sinkhole/honeypot -> CPE-INFECTADO,
#      o CPE-IOT-PROPAGA / CPE-IOT-LATERAL) se ESCALA a CONFIRMADO.
#
#  COSTO: si la tabla supera EVGCONNMAXSCAN, se omite el conteo pesado y
#  solo se avisa, para no clavar la CPU. Corre cada hora.
#
add name=EVG-CALIBRA owner=admin policy=read,write,test source={
# --- defaults reboot-safe: los globales se pierden en un reboot, aqui se
#     re-siembran si faltan (la REGLA guarda el valor aprendido igual) ---
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
:log info "EVG-CALIBRA: inicio"

# ---- (4) EVG-NO-AUTOBLOCK: union de infra de confianza  [FP-03] ----------
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
      :log warning ("EVG-CALIBRA: 6969 CORROBORADO -> " . $ip . " (aparece en señal dura) -> CONFIRMADO")
      :set escalados ($escalados + 1)
    }
  } on-error={}
}

# ---- pasada unica por conexiones: (1) conteo por src, (2) proxy, (3) DoT --
:local nConn [:len [/ip firewall connection find]]
:if ($nConn > $EVGCONNMAXSCAN) do={
  :log warning ("EVG-CALIBRA: " . $nConn . " conexiones (> EVGCONNMAXSCAN=" . $EVGCONNMAXSCAN . "). Se OMITE el conteo pesado para no clavar la CPU. Subir el intervalo/tope o fijar EVGCONNFLOOD a mano.")
} else={
  :local cnt [:toarray ""]
  :local flows [:toarray ""]
  :local dotcount [:toarray ""]
  :local dotseen [:toarray ""]

  :foreach c in=[/ip firewall connection find] do={
    :do {
      :local sa [:tostr [/ip firewall connection get $c src-address]]
      :local cp [:find $sa ":"]
      :local ip $sa
      :if ([:typeof $cp] = "num") do={ :set ip [:pick $sa 0 $cp] }
      :local ipa [:toip $ip]
      :if ([:typeof $ipa] = "ip") do={
        # (1) conteo de conexiones por cliente interno
        :local interno false
        :if ($ipa in 10.0.0.0/8)     do={ :set interno true }
        :if ($ipa in 172.16.0.0/12)  do={ :set interno true }
        :if ($ipa in 192.168.0.0/16) do={ :set interno true }
        :if ($ipa in 100.64.0.0/10)  do={ :set interno true }
        :if ($interno) do={
          :local cur ($cnt->$ip)
          :if ([:typeof $cur] = "nothing") do={ :set cur 0 }
          :set ($cnt->$ip) ($cur + 1)
        }
        :if ([:tostr [/ip firewall connection get $c protocol]] = "tcp") do={
          # (2) proxy por simetria: contar flujos grandes y simetricos por src
          :local ob [/ip firewall connection get $c orig-bytes]
          :local rb [/ip firewall connection get $c repl-bytes]
          :if (($ob > $minB) and ($rb > $minB)) do={
            :local hi $ob
            :local lo $rb
            :if ($rb > $ob) do={ :set hi $rb; :set lo $ob }
            :if (($lo * $factor) > $hi) do={
              :local curf ($flows->$ip)
              :if ([:typeof $curf] = "nothing") do={ :set curf 0 }
              :set ($flows->$ip) ($curf + 1)
            }
          }
          # (3) DoT: clientes distintos por destino :853
          :local da [:tostr [/ip firewall connection get $c dst-address]]
          :local dcp [:find $da ":"]
          :if ([:typeof $dcp] = "num") do={
            :local dip [:pick $da 0 $dcp]
            :local dpt [:pick $da ($dcp + 1) [:len $da]]
            :if ($dpt = "853") do={
              :local pair ($dip . "|" . $ip)
              :if ([:typeof ($dotseen->$pair)] = "nothing") do={
                :set ($dotseen->$pair) true
                :local curd ($dotcount->$dip)
                :if ([:typeof $curd] = "nothing") do={ :set curd 0 }
                :set ($dotcount->$dip) ($curd + 1)
              }
            }
          }
        }
      }
    } on-error={}
  }

  # --- (1) umbral de conexiones: cliente mas ocupado ---
  :local busy 0
  :local busyip ""
  :foreach k,v in=$cnt do={
    :if ($v > $busy) do={ :set busy $v; :set busyip $k }
  }
  # leer el umbral ACTUAL desde la regla (persiste en config, sobrevive reboot)
  :local actual $EVGCONNFLOORMIN
  :do {
    :local s [:tostr [/ip firewall filter get [find where comment~"DETECTA exceso de conexiones"] connection-limit]]
    :local com [:find $s ","]
    :if ([:typeof $com] = "num") do={ :set actual [:tonum [:pick $s 0 $com]] }
  } on-error={}
  :local target ($busy * 2)
  :if ($target < $EVGCONNFLOORMIN) do={ :set target $EVGCONNFLOORMIN }
  :if ($target > $EVGCONNFLOORMAX) do={ :set target $EVGCONNFLOORMAX }
  :local dif ($target - $actual)
  :if ($dif < 0) do={ :set dif (0 - $dif) }
  :local paso (($actual * 15) / 100)
  :if ($dif > $paso) do={
    :set EVGCONNFLOOD $target
    :do { /ip firewall filter set [find where comment~"DETECTA exceso de conexiones"] connection-limit=("$target,32") } on-error={}
    :do { /ip firewall filter set [find where comment~"OPT-CONEXIONES"] connection-limit=("$target,32") } on-error={}
    :log warning ("EVG-CALIBRA: umbral de conexiones " . $actual . " -> " . $target . " (cliente top " . $busyip . " con " . $busy . " conexiones)")
  } else={
    :set EVGCONNFLOOD $actual
    :log info ("EVG-CALIBRA: umbral de conexiones se mantiene en " . $actual . " (cliente top " . $busy . ")")
  }

  # --- (2) proxies: >= EVGPROXYMINFLOWS flujos grandes simetricos ---
  :local nProxy 0
  :foreach k,v in=$flows do={
    :if ($v >= $EVGPROXYMINFLOWS) do={
      :if ([:len [/ip firewall address-list find where list="CPE-PROXY" and address=$k]] = 0) do={
        :do {
          /ip firewall address-list add list=CPE-PROXY address=$k timeout=7d comment=("EVG-PROXY-DATA " . $v . " flujos simetricos")
          :set nProxy ($nProxy + 1)
          :log warning ("EVG-CALIBRA: posible proxy " . $k . " con " . $v . " flujos grandes simetricos a la vez")
        } on-error={}
      }
    }
  }

  # --- (3) DoT por consenso: destino usado por muchos clientes -> DNS-OK ---
  :local nDot 0
  :foreach k,v in=$dotcount do={
    :if ($v >= $EVGDOTMINCLIENTES) do={
      :if ([:len [/ip firewall address-list find where list="DNS-OK" and address=$k]] = 0) do={
        :do {
          /ip firewall address-list add list=DNS-OK address=$k timeout=30d comment=("EVG-AUTO DoT consenso " . $v . " clientes")
          :set nDot ($nDot + 1)
          :log info ("EVG-CALIBRA: DoT " . $k . " usado por " . $v . " clientes distintos -> DNS-OK")
        } on-error={}
      } else={
        :do {
          :foreach e in=[/ip firewall address-list find where list="DNS-OK" and address=$k and comment~"EVG-AUTO"] do={
            /ip firewall address-list set $e timeout=30d
          }
        } on-error={}
      }
    }
  }

  :log info ("EVG-CALIBRA: conexiones=" . $nConn . " proxies-nuevos=" . $nProxy . " DoT-consenso=" . $nDot)
}

:log warning ("EVG-CALIBRA: fin | umbral-conexiones=" . $EVGCONNFLOOD . " | 6969-escalados=" . $escalados . " | no-autobloqueo=" . [:len [/ip firewall address-list find where list="EVG-NO-AUTOBLOCK"]])
}

# ============================================================================
# --- 9.6 EVG-AUDIT: EL FIREWALL SE REVISA A SI MISMO  [NEW-02]
# ============================================================================
#
#  Busca exactamente los tipos de fallo que aparecieron una y otra vez en
#  las versiones anteriores. Corre cada hora.
#
#  Leer con:  /log print where message~"EVG-AUDIT"
#
add name=EVG-AUDIT owner=admin policy=read,write,test source={
:local fallas 0

# A. Interface-lists pobladas
:if ([:len [/interface list member find where list="LAN"]] = 0) do={
  :log error "EVG-AUDIT: FALLA -- interface-list LAN VACIA. La deteccion de la SECCION 6B cuenta CERO."
  :set fallas ($fallas + 1)
}
:if ([:len [/interface list member find where list="WAN"]] = 0) do={
  :log error "EVG-AUDIT: FALLA -- interface-list WAN VACIA."
  :set fallas ($fallas + 1)
}

# B. Listas referenciadas con `!` que existen
#    Una lista vacia hace que !LISTA matchee SIEMPRE. Ese bug bloqueo SQL
#    y RDP a todos los clientes en v7.6.
:foreach L in={"SMTP-ALLOWED";"SSH-ALLOWED";"RDP-ALLOWED";"DB-ALLOWED";"DNS-OK"} do={
  :if ([:len [/ip firewall address-list find where list=$L]] = 0) do={
    :log error ("EVG-AUDIT: FALLA -- la lista " . $L . " esta VACIA. Cualquier regla con !" . $L . " matchea TODO.")
    :set fallas ($fallas + 1)
  }
}

# B2. Consistencia del honeypot  [FIX-43]
#     La regla 6B.2 matchea HONEYPOT-INTERNO. Si por error quedaron dark-IP
#     en la vieja lista EVG-HONEYPOT (v7.12), no detectan nada: avisar.
:if ([:len [/ip firewall address-list find where list="EVG-HONEYPOT"]] > 0) do={
  :log error "EVG-AUDIT: FALLA -- hay entradas en la lista OBSOLETA EVG-HONEYPOT. La regla 6B.2 solo mira HONEYPOT-INTERNO. Mover esas dark-IP a HONEYPOT-INTERNO (o correr EVG-DESCUBRE, que ya la usa)."
  :set fallas ($fallas + 1)
}

# C. Reglas con `limit` en un add-to-address-list (logica invertida)
:foreach r in=[/ip firewall filter find where action="add-src-to-address-list" and disabled=no] do={
  :do {
    :if ([:len [/ip firewall filter get $r limit]] > 0) do={
      :log error ("EVG-AUDIT: FALLA -- regla con `limit` en add-to-address-list: " . [/ip firewall filter get $r comment] . " -- logica INVERTIDA, usar dst-limit con mode=src-address.")
      :set fallas ($fallas + 1)
    }
  } on-error={}
}

# D. Conntrack: timeouts de fabrica y ocupacion
:local ut [/ip firewall connection tracking get udp-timeout]
:if ($ut > 15s) do={
  :log error ("EVG-AUDIT: FALLA -- udp-timeout en " . $ut . ". Con drop de invalid en forward, ROMPE QUIC. Fabrica: 10s.")
  :set fallas ($fallas + 1)
}
:local ctT [/ip firewall connection tracking get total-entries]
:local ctM [/ip firewall connection tracking get max-entries]
:local pct (($ctT * 100) / $ctM)
:if ($pct > 70) do={
  :log error ("EVG-AUDIT: FALLA -- conntrack al " . $pct . "% (" . $ctT . "/" . $ctM . "). Las conexiones NUEVAS empiezan a fallar y el primero en notarlo es el que mas consume.")
  :set fallas ($fallas + 1)
}

# E. Drop de invalid en forward activo
:if ([:len [/ip firewall filter find where chain="forward" and connection-state="invalid" and action="drop" and disabled=no]] > 0) do={
  :log warning "EVG-AUDIT: hay un drop de invalid en FORWARD activo. Es el principal sospechoso del incidente. Verificar que udp-timeout este en fabrica."
}

# F. Listas de deteccion desbordadas
#    Si una deteccion marca a decenas de clientes, esta mal calibrada.
#    Paso con la de proxy: 188 falsos positivos.
:foreach L in={"CPE-BRUTEFORCE";"CPE-IOT-PROPAGA";"CPE-IOT-LATERAL";"CPE-PROXY";"CPE-CONNFLOOD";"CPE-DOT-RARO";"CPE-SQL-SALIENTE"} do={
  :local n [:len [/ip firewall address-list find where list=$L]]
  :if ($n > 30) do={
    :log error ("EVG-AUDIT: FALLA -- la lista " . $L . " tiene " . $n . " entradas. Eso NO son " . $n . " infectados: la deteccion esta mal calibrada. NO activar el OPT- correspondiente.")
    :set fallas ($fallas + 1)
  }
}

# G. ICMP: ninguna regla de echo-REPLY puede tener limite  [FIX-42]
#    Limitar la respuesta rompe check-gateway y tumba la ruta.
:foreach r in=[/ip firewall filter find where chain="input" and action="accept" and disabled=no] do={
  :do {
    :if ([/ip firewall filter get $r icmp-options] = "0:0") do={
      :if ([:len [/ip firewall filter get $r limit]] > 0) do={
        :log error "EVG-AUDIT: FALLA -- la regla de ICMP echo-reply tiene `limit`. Eso rompe check-gateway y tumba la ruta con failover. Quitar el limite."
        :set fallas ($fallas + 1)
      }
    }
  } on-error={}
}

# G2. Si hay check-gateway, la lista GATEWAYS no puede estar vacia
:local nCg [:len [/ip route find where check-gateway="ping"]]
:if ($nCg > 0) do={
  :local nGw [:len [/ip firewall address-list find where list="GATEWAYS"]]
  :if ($nGw < 2) do={
    :log error ("EVG-AUDIT: FALLA -- hay " . $nCg . " rutas con check-gateway=ping pero la lista GATEWAYS tiene solo " . $nGw . " entrada(s). Riesgo de que la ruta se caiga sola.")
    :set fallas ($fallas + 1)
  }
}

# G3. Spamhaus con conteo razonable
:local sh [:len [/ip firewall address-list find where list="SPAMHAUS-DROP"]]
:if (($sh > 0) and ($sh < 300)) do={
  :log error ("EVG-AUDIT: FALLA -- SPAMHAUS-DROP tiene solo " . $sh . " entradas. Descarga incompleta: puede estar bloqueando rangos equivocados.")
  :set fallas ($fallas + 1)
}

# G4. Umbral autocalibrado de conexiones dentro de un rango sensato  [NEW-09]
#     Si EVG-CALIBRA por un bug lo puso en 0 (bloquearia todo si se activa el
#     OPT) o en un valor absurdo, avisar. Se lee de la propia regla.
:do {
  :local s [:tostr [/ip firewall filter get [find where comment~"DETECTA exceso de conexiones"] connection-limit]]
  :local com [:find $s ","]
  :if ([:typeof $com] = "num") do={
    :local val [:tonum [:pick $s 0 $com]]
    :if (($val < 100) or ($val > 8000)) do={
      :log error ("EVG-AUDIT: FALLA -- umbral de conexiones (6B.5) en " . $val . ", fuera de rango sensato [100..8000]. Revisar EVG-CALIBRA o fijar EVGCONNFLOOD a mano.")
      :set fallas ($fallas + 1)
    }
  }
} on-error={}

# G5. EVG-NO-AUTOBLOCK no debe contener 0.0.0.0/0 (dejaria ciego al detector)
:if ([:len [/ip firewall address-list find where list="EVG-NO-AUTOBLOCK" and address="0.0.0.0/0"]] > 0) do={
  :log error "EVG-AUDIT: FALLA -- EVG-NO-AUTOBLOCK contiene 0.0.0.0/0: el detector honeypot de INPUT quedaria desactivado. Quitar esa entrada."
  :set fallas ($fallas + 1)
}

# H. Cuantos drops activos hay sobre trafico de clientes
:log info ("EVG-AUDIT: drops ACTIVOS en forward = " . [:len [/ip firewall filter find where chain="forward" and action="drop" and disabled=no]])

# I. Equipo
:if ([/system resource get cpu-load] > 80) do={
  :log error ("EVG-AUDIT: FALLA -- CPU en " . [/system resource get cpu-load] . "%")
  :set fallas ($fallas + 1)
}
:if ([:len [/user find where name="admin"]] > 0) do={
  :log warning "EVG-AUDIT: existe el usuario 'admin' por defecto."
}
:do {
  :if ([/tool mac-server mac-winbox get [find] allowed-interface-list] = "all") do={
    :log warning "EVG-AUDIT: MAC-Winbox en TODAS las interfaces. El acceso por MAC SALTA el firewall IP."
  }
} on-error={}

# Resumen
:if ($fallas = 0) do={
  :log info "EVG-AUDIT: OK -- sin fallas detectadas"
} else={
  :log error ("EVG-AUDIT: " . $fallas . " FALLA(S) -- revisar las lineas de error de arriba")
}
}

# ============================================================================
# --- 9.7 EVG-AUDIT-EXPOSICION: de donde entran  [NEW-05]
# ============================================================================
#
#  Encuentra las reglas dst-nat que exponen un servicio a TODO internet sin
#  restriccion de origen. En el caso de INTEDCOL ahi estaba la via de
#  entrada: el SSH de la OLT, un servidor con SSH en el 22 directo, y el
#  Winbox de dos clientes empresariales.
#
#  Y cruza esa exposicion con los infectados: si en la misma subred hay un
#  equipo expuesto y uno infectado, ese es el camino que siguio el malware.
#  En INTEDCOL dio tres coincidencias.
#
#  Leer con:  /log print where message~"EVG-EXPOSICION"
#
add name=EVG-AUDIT-EXPOSICION owner=admin policy=read,write,test source={
:log warning "=== EVG-EXPOSICION: auditoria de dst-nat ==="
:local abiertas 0
:local criticas 0

:foreach r in=[/ip firewall nat find where chain="dstnat" and action="dst-nat" and disabled=no] do={
  :do {
    :local sl [/ip firewall nat get $r src-address-list]
    :local sa [/ip firewall nat get $r src-address]
    :if (([:len $sl] = 0) and ([:len $sa] = 0)) do={
      :local dp [:tostr [/ip firewall nat get $r dst-port]]
      :local pr [:tostr [/ip firewall nat get $r protocol]]
      :local tp [:tostr [/ip firewall nat get $r to-ports]]
      :local ta [:tostr [/ip firewall nat get $r to-addresses]]
      :local da [:tostr [/ip firewall nat get $r dst-address]]
      :local cm [/ip firewall nat get $r comment]

      # --- NAT 1:1 completo: sin dst-port NI protocol ---
      # Es lo peor que hay. No expone un puerto: expone el equipo entero,
      # los 65535 puertos, a todo internet. Si detras hay una camara o un
      # DVR con contrasena de fabrica, Mirai lo encuentra en horas.
      #
      # Puede ser deliberado (un hotel con su propio bloque publico) o
      # puede ser que se hizo asi porque era mas rapido. El script no lo
      # puede saber, asi que solo avisa.
      :if (([:len $dp] = 0) and ([:len $pr] = 0)) do={
        :log error ("EVG-EXPOSICION: NAT 1:1 COMPLETO | " . $cm . " | " . \
          $da . " -> " . $ta . "  <<< LOS 65535 PUERTOS EXPUESTOS")
        :set criticas ($criticas + 1)
      } else={
        :local nivel ""
        :foreach p in={"22";"23";"80";"443";"8291";"8728";"8729";"3389";"5900";"161"} do={
          :if ($tp = $p) do={ :set nivel "  <<< SERVICIO DE ADMINISTRACION" }
          :if (($tp = "") and ($dp = $p)) do={ :set nivel "  <<< SERVICIO DE ADMINISTRACION" }
        }
        :if ([:len $nivel] > 0) do={
          :log error ("EVG-EXPOSICION: " . $cm . " | puerto " . $dp . " -> " . $ta . ":" . $tp . $nivel)
          :set criticas ($criticas + 1)
        } else={
          :log warning ("EVG-EXPOSICION: " . $cm . " | puerto " . $dp . " -> " . $ta . ":" . $tp)
        }
      }
      :set abiertas ($abiertas + 1)
    }
  } on-error={}
}

:if ($abiertas = 0) do={
  :log info "EVG-EXPOSICION: ningun dst-nat sin restriccion de origen"
} else={
  :log error ("EVG-EXPOSICION: " . $abiertas . " regla(s) dst-nat abiertas a todo internet, " . $criticas . " criticas (NAT 1:1 o servicio de administracion). Restringir con src-address-list, o acotar por dst-port si el 1:1 no es necesario.")
}

# --- Cruce: subredes donde hay un expuesto Y un infectado ---
:local cruces 0
:foreach inf in=[/ip firewall address-list find where list="CPE-INFECTADO"] do={
  :do {
    :local ipi [/ip firewall address-list get $inf address]
    :local p1 [:find $ipi "." 0]
    :local p2 [:find $ipi "." ($p1 + 1)]
    :local p3 [:find $ipi "." ($p2 + 1)]
    :local red [:pick $ipi 0 $p3]
    :foreach r in=[/ip firewall nat find where chain="dstnat" and action="dst-nat" and disabled=no] do={
      :do {
        :local ta [:tostr [/ip firewall nat get $r to-addresses]]
        :if ([:find $ta ($red . ".") 0] = 0) do={
          :log error ("EVG-EXPOSICION: PROPAGACION PROBABLE en " . $red . ".0/24 -- expuesto " . $ta . " / infectado " . $ipi)
          :set cruces ($cruces + 1)
        }
      } on-error={}
    }
  } on-error={}
}
:if ($cruces > 0) do={
  :log error ("EVG-EXPOSICION: " . $cruces . " coincidencia(s) expuesto/infectado en la misma subred. Ese es el camino del malware.")
}

# --- Servicios del propio router alcanzables desde WAN ---
:foreach s in=[/ip service find where disabled=no] do={
  :do {
    :local nm [/ip service get $s name]
    :local ad [:tostr [/ip service get $s address]]
    :if ([:len $ad] = 0) do={
      :log warning ("EVG-EXPOSICION: el servicio " . $nm . " no tiene restriccion de origen (/ip service set " . $nm . " address=...)")
    }
  } on-error={}
}
:log warning "=== FIN EVG-EXPOSICION ==="
}

# ============================================================================
# --- 9.8 EVG-RBL-CHECK: el router se consulta a si mismo  [NEW-07]
# ============================================================================
#
#  Toma TODAS las publicas de salida del propio equipo, las invierte, y
#  pregunta a cuatro listas negras si estan marcadas.
#
#  DE DONDE SACA LAS IP  (las dos fuentes, sin duplicar)
#    1. /ip address  -- las asignadas al router que no son privadas
#    2. /ip firewall nat  -- los to-addresses de las reglas src-nat, que
#       son las publicas por donde realmente salen los clientes
#
#    La segunda fuente importa: en un ISP con NAT por address-list, las
#    publicas de salida pueden no estar todas en /ip address.
#
#  LISTAS QUE CONSULTA
#    all.s5h.net              proxies y hosts comprometidos
#    zen.spamhaus.org         SBL + XBL + PBL de Spamhaus
#    b.barracudacentral.org   Barracuda
#    all.spamrats.com         SpamRats
#
#  RETIRO AUTOMATICO
#    Solo s5h ofrece autoservicio. Si sale listada ahi, el script pide el
#    retiro CON src-address de esa IP -- si no, el retiro se aplicaria a la
#    IP por defecto del router y no a la que esta listada.
#
#    Spamhaus, Barracuda y SpamRats NO se retiran solos: hay que entrar al
#    sitio de cada uno. Y ojo: pedir el retiro ANTES de cortar la emision
#    solo consigue que vuelva a listarse, y la segunda vez cuesta mas.
#
#  REQUISITOS
#    El router tiene que resolver DNS:  /ip dns print
#
add name=EVG-RBL-CHECK owner=admin policy=read,write,test,policy source={
:local rbls {"all.s5h.net";"zen.spamhaus.org";"b.barracudacentral.org";"all.spamrats.com"}
:local urlS5H "http://www.usenix.org.uk/content/rblremove"
:local ips [:toarray ""]

# --- Aviso si el router resuelve contra un resolver publico ---------------
# Spamhaus RECHAZA las consultas que llegan desde 8.8.8.8, 1.1.1.1 y demas
# resolvers abiertos, y responde 127.255.255.254 -- que NO significa
# listada, significa "consulta invalida". Si el router usa uno de esos, los
# resultados de Spamhaus no sirven.
:local dnsPublico false
:do {
  :local svr [:tostr [/ip dns get servers]]
  :foreach p in={"8.8.8.8";"8.8.4.4";"1.1.1.1";"1.0.0.1";"9.9.9.9";"208.67.222.222"} do={
    :if ([:typeof [:find $svr $p]] != "nil") do={ :set dnsPublico true }
  }
} on-error={}
:if ($dnsPublico) do={
  :log warning "EVG-RBL: el router resuelve contra un DNS publico. Spamhaus RECHAZA esas consultas y responde 127.255.255.254, que NO es un listado. Para que Spamhaus sirva, apuntar /ip dns a un resolver propio."
}

# --- fuente 1: direcciones del propio router ---
:foreach a in=[/ip address find where disabled=no] do={
  :do {
    :local adr [/ip address get $a address]
    :local net [/ip address get $a network]
    :local priv false
    :if ($net in 10.0.0.0/8)     do={ :set priv true }
    :if ($net in 172.16.0.0/12)  do={ :set priv true }
    :if ($net in 192.168.0.0/16) do={ :set priv true }
    :if ($net in 127.0.0.0/8)    do={ :set priv true }
    :if ($net in 169.254.0.0/16) do={ :set priv true }
    :if ($net in 100.64.0.0/10)  do={ :set priv true }
    :if ($net in 224.0.0.0/4)    do={ :set priv true }
    :if (!$priv) do={
      :local host [:pick $adr 0 [:find $adr "/"]]
      :if ([:typeof [:find $ips $host]] = "nil") do={ :set ips ($ips , $host) }
    }
  } on-error={}
}

# --- fuente 2: las publicas de salida del NAT ---
:foreach n in=[/ip firewall nat find where chain="srcnat" and action="src-nat" and disabled=no] do={
  :do {
    :local ta [:tostr [/ip firewall nat get $n to-addresses]]
    :if ([:len $ta] > 6) do={
      :if ([:typeof [:find $ta "-"]] = "nil") do={
        :if ([:typeof [:find $ips $ta]] = "nil") do={ :set ips ($ips , $ta) }
      }
    }
  } on-error={}
}

:if ([:len $ips] = 0) do={
  :log warning "EVG-RBL: no se detecto ninguna IP publica de salida"
} else={
  :log warning ("=== EVG-RBL: consultando " . [:len $ips] . " IP publica(s) ===")
}

/ip firewall address-list remove [find where list="EVG-RBL-LISTADA" and comment~"EVG-RBL-AUTO"]
/ip firewall address-list remove [find where list="EVG-RBL-SIN-PTR" and comment~"EVG-RBL-AUTO"]

:local nReal 0
:local nPtr 0
:local nInval 0
:local s5hPendientes [:toarray ""]

:foreach ip in=$ips do={
  # invertir los octetos: 1.2.3.4 -> 4.3.2.1
  :local p1 [:find $ip "." 0]
  :local p2 [:find $ip "." ($p1 + 1)]
  :local p3 [:find $ip "." ($p2 + 1)]
  :local inv ([:pick $ip ($p3 + 1) [:len $ip]] . "." . [:pick $ip ($p2 + 1) $p3] . "." . \
              [:pick $ip ($p1 + 1) $p2] . "." . [:pick $ip 0 $p1])

  :local real ""
  :local ptr ""
  :local inval ""
  :local enS5H false

  :foreach rbl in=$rbls do={
    :do {
      :local r [:tostr [:resolve ($inv . "." . $rbl)]]

      # --- INTERPRETAR EL CODIGO DE RESPUESTA ---
      #
      # No todo lo que resuelve es una infeccion. Hay tres casos y mezclarlos
      # hace que el reporte diga 30 listadas cuando en realidad hay 2.
      #
      #   127.255.255.x   consulta RECHAZADA (resolver publico, o sin
      #                   suscripcion). NO es un listado.
      #   127.0.0.36/37   SpamRats RATS-NoPtr: la IP no tiene registro PTR
      #                   inverso. Es configuracion faltante, NO malware.
      #   el resto        listado real
      #
      :if ([:typeof [:find $r "127.255.255."]] != "nil") do={
        :set inval ($inval . $rbl . " ")
      } else={
        :if (($r = "127.0.0.36") or ($r = "127.0.0.37")) do={
          :set ptr ($ptr . $rbl . " ")
        } else={
          :set real ($real . $rbl . "(" . $r . ") ")
          :if ($rbl = "all.s5h.net") do={ :set enS5H true }
        }
      }
    } on-error={
      # NXDOMAIN = no listada. Es el caso normal.
    }
  }

  :if ([:len $real] > 0) do={
    :log error ("EVG-RBL: " . $ip . " LISTADA -> " . $real)
    :do {
      /ip firewall address-list add list="EVG-RBL-LISTADA" address=$ip \
        comment=("EVG-RBL-AUTO " . $real)
    } on-error={}
    :set nReal ($nReal + 1)
    :if ($enS5H) do={ :set s5hPendientes ($s5hPendientes , $ip) }
  }

  :if (([:len $ptr] > 0) and ([:len $real] = 0)) do={
    :do {
      /ip firewall address-list add list="EVG-RBL-SIN-PTR" address=$ip \
        comment="EVG-RBL-AUTO sin registro PTR inverso"
    } on-error={}
    :set nPtr ($nPtr + 1)
  }

  :if (([:len $inval] > 0) and ([:len $real] = 0) and ([:len $ptr] = 0)) do={
    :set nInval ($nInval + 1)
  }

  :if (([:len $real] = 0) and ([:len $ptr] = 0)) do={
    :log info ("EVG-RBL: " . $ip . " limpia")
  }
}

# --- retiro automatico en s5h, con el origen correcto ---
:foreach ip in=$s5hPendientes do={
  :do {
    /tool fetch url=$urlS5H mode=http output=none src-address=$ip
    :log warning ("EVG-RBL: retiro de s5h solicitado para " . $ip)
  } on-error={
    :log error ("EVG-RBL: fallo el retiro de s5h para " . $ip . \
      " (revisar DNS, ruta de salida, o que la IP este en el router)")
  }
}

# --- RESUMEN, separando lo que es cada cosa ---
:if ($nReal = 0) do={
  :log warning "EVG-RBL: ninguna publica con listado real"
} else={
  :log error ("EVG-RBL: " . $nReal . " IP con LISTADO REAL. Ver: " . \
    "/ip firewall address-list print where list=EVG-RBL-LISTADA")
  :log error "EVG-RBL: s5h se retira solo. Spamhaus, Barracuda y SpamRats a mano, y SOLO despues de 48h sin emision."
}
:if ($nPtr > 0) do={
  :log warning ("EVG-RBL: " . $nPtr . " IP SIN PTR INVERSO (RATS-NoPtr). Esto NO es infeccion: " . \
    "es delegacion inversa faltante. Pedirla al upstream. Ver: " . \
    "/ip firewall address-list print where list=EVG-RBL-SIN-PTR")
}
:if ($nInval > 0) do={
  :log warning ("EVG-RBL: " . $nInval . " consulta(s) rechazadas por la lista (codigo 127.255.255.x). " . \
    "Suele ser por resolver publico: apuntar /ip dns a un recursivo propio.")
}
:log warning "=== FIN EVG-RBL ==="
}

/system scheduler
add name=EVG-DESCUBRE on-event=EVG-DESCUBRE interval=30m start-time=startup policy=read,write,test comment="EVG-FW2026 | Autodescubrimiento de interfaces y rangos"
add name=EVG-POPULATE on-event=EVG-POPULATE interval=10m start-time=startup policy=read,write,test comment="EVG-FW2026 | Auto-poblado cada 10m"
add name=EVG-UPDATE-SPAMHAUS on-event=EVG-UPDATE-SPAMHAUS interval=1d start-time=startup policy=read,write,test,reboot comment="EVG-FW2026 | Spamhaus diario"
add name=EVG-AUTO-OFF-BYPASS on-event=EVG-AUTO-OFF-BYPASS interval=5m start-time=startup policy=read,write,test comment="EVG-FW2026 | Auto-off bypass 5m"
add name=EVG-QUARANTINE-REPORT on-event=EVG-QUARANTINE-REPORT interval=1d start-time=08:00:00 policy=read,write,test comment="EVG-FW2026 | Reporte diario 8am"
add name=EVG-CALIBRA on-event=EVG-CALIBRA interval=1h start-time=startup policy=read,write,test comment="EVG-FW2026 | Autocalibracion de umbrales + proxy/DoT/6969 (ex EVG-PROXY)"
add name=EVG-AUDIT on-event=EVG-AUDIT interval=1h start-time=startup policy=read,write,test comment="EVG-FW2026 | AUTODIAGNOSTICO"
add name=EVG-AUDIT-EXPOSICION on-event=EVG-AUDIT-EXPOSICION interval=6h start-time=startup policy=read,write,test comment="EVG-FW2026 | Auditoria de exposicion dst-nat"
add name=EVG-RBL-CHECK on-event=EVG-RBL-CHECK interval=1d start-time=06:00:00 policy=read,write,test,policy comment="EVG-FW2026 | Consulta de listas negras 6am"

# ============================================================================
# SECCION 10 - IPv6 FIREWALL
# ============================================================================
/ipv6 firewall address-list
add address=fe80::/10 list=IPv6-LINKLOCAL comment="EVG-FW2026 | IPv6 link-local"
add address=fc00::/7  list=IPv6-ULA       comment="EVG-FW2026 | IPv6 ULA"

/ipv6 firewall raw
add action=drop chain=prerouting src-address=::/128             comment="EVG-FW2026 | IPv6 unspecified"
add action=drop chain=prerouting src-address=::1/128            comment="EVG-FW2026 | IPv6 loopback como src"
add action=drop chain=prerouting src-address=::ffff:0.0.0.0/96  comment="EVG-FW2026 | IPv4-mapped"
add action=drop chain=prerouting src-address=2001:db8::/32      comment="EVG-FW2026 | IPv6 documentacion"

/ipv6 firewall filter
add action=accept chain=input disabled=yes comment="EVG-FW2026 | BYPASS-V6: NO activar salvo emergencia"
add action=accept chain=input connection-state=established,related comment="EVG-FW2026 | IPv6 IN: established/related"
add action=drop chain=input connection-state=invalid comment="EVG-FW2026 | IPv6 IN: invalid"
add action=accept chain=input protocol=icmpv6 comment="EVG-FW2026 | IPv6 ICMPv6 (RFC4890: OBLIGATORIO)"
add action=accept chain=input src-address=fe80::/10 comment="EVG-FW2026 | IPv6 link-local"
add action=accept chain=input protocol=udp dst-port=546 src-address=fe80::/10 comment="EVG-FW2026 | DHCPv6 client"
add action=accept chain=input protocol=udp dst-port=547 src-address=fe80::/10 comment="EVG-FW2026 | DHCPv6 server (link-local)"
add action=accept chain=input protocol=udp dst-port=547 in-interface-list=LAN comment="EVG-FW2026 | DHCPv6 server (LAN)"

# --- RUTEO IPv6  [FIX-39] --------------------------------------------------
# Faltaba en v7.6: con el DROP FINAL, cualquier sesion de ruteo IPv6 se caia.
add action=accept chain=input protocol=ospf comment="EVG-FW2026 | IPv6 OSPFv3"
add action=accept chain=input protocol=tcp dst-port=179 src-address-list=V6-BGP-PEERS comment="EVG-FW2026 | IPv6 BGP desde peers"

add action=drop chain=input in-interface-list=WAN comment="EVG-FW2026 | IPv6 DROP FINAL INPUT WAN"

add action=accept chain=forward connection-state=established,related comment="EVG-FW2026 | IPv6 FWD: established/related"
# Igual que en IPv4: el drop de invalid queda DESHABILITADO.
add action=drop chain=forward connection-state=invalid disabled=yes comment="EVG-FW2026 | OPT-INVALID-V6 (mismo riesgo que en IPv4)"
add action=accept chain=forward protocol=icmpv6 comment="EVG-FW2026 | IPv6 FWD ICMPv6"

# Puertos peligrosos HACIA clientes: en IPv6 no hay NAT, cada host queda
# expuesto directo a internet.
# [FIX-46] El 7547 (TR-069) SALE del bloqueo activo, igual que en IPv4: si
# el ISP aprovisiona los CPE con un ACS alcanzable por IPv6, cortarlo le
# rompe la gestion de toda la base. Queda como OPT-V6-7547 (deshabilitado)
# para activarlo solo quien NO use ACS sobre IPv6.
add action=drop chain=forward protocol=tcp dst-port=23,2323,445,135-139,3389,5555,37215,52869 in-interface-list=WAN comment="EVG-FW2026 | IPv6 puertos peligrosos hacia clientes"
add action=drop chain=forward protocol=tcp dst-port=7547 in-interface-list=WAN disabled=yes comment="EVG-FW2026 | OPT-V6-7547 (bloquea TR-069 hacia clientes: activar solo si NO aprovisionas por ACS sobre IPv6)"
add action=drop chain=forward protocol=udp dst-port=445,137-138,5555 in-interface-list=WAN comment="EVG-FW2026 | IPv6 puertos peligrosos UDP"

# Egress IPv6
add action=drop chain=forward protocol=tcp dst-port=445 out-interface-list=WAN comment="EVG-FW2026 | IPv6 Drop SMB outbound"
add action=drop chain=forward protocol=tcp dst-port=135-139 out-interface-list=WAN comment="EVG-FW2026 | IPv6 Drop NetBIOS outbound"
add action=drop chain=forward protocol=tcp dst-port=25 out-interface-list=WAN comment="EVG-FW2026 | IPv6 Drop 25/TCP outbound"
add action=drop chain=forward protocol=tcp dst-port=6660-6669,6697 out-interface-list=WAN disabled=yes comment="EVG-FW2026 | OPT-IRC-V6"

add action=drop chain=forward connection-state=new in-interface-list=WAN disabled=yes comment="EVG-FW2026 | OPT-V6-CERRADO (rompe end-to-end IPv6)"

# ============================================================================
# CARGA INICIAL
# ============================================================================
# El descubrimiento va PRIMERO: el resto de las reglas depende de las
# listas que puebla. Si corre despues, todo cuenta cero.
/system script run EVG-DESCUBRE
/system script run EVG-POPULATE
/system script run EVG-CALIBRA
/system script run EVG-UPDATE-SPAMHAUS
/system script run EVG-AUDIT
/system script run EVG-AUDIT-EXPOSICION
/system script run EVG-RBL-CHECK

# ============================================================================
# VERIFICACION FINAL
# ============================================================================
:local rIn  [:len [/ip firewall filter find where chain=input and comment~"EVG-FW2026"]]
:local rFw  [:len [/ip firewall filter find where chain=forward and comment~"EVG-FW2026"]]
:local rOut [:len [/ip firewall filter find where chain=output and comment~"EVG-FW2026"]]
:local rSyn [:len [/ip firewall filter find where chain=SYN-PROT and comment~"EVG-FW2026"]]
:local rBf  [:len [/ip firewall filter find where chain=EVG-EGRESS-BF and comment~"EVG-FW2026"]]
:local rRaw [:len [/ip firewall raw find where comment~"EVG-FW2026"]]
:local rV6f [:len [/ipv6 firewall filter find where comment~"EVG-FW2026"]]
:local rV6r [:len [/ipv6 firewall raw find where comment~"EVG-FW2026"]]
:local dAct [:len [/ip firewall filter find where chain=forward and action="drop" and disabled=no]]
:local aQ   [:len [/ip firewall address-list find where list=CPE-QUARANTINE]]
:local aHp  [:len [/ip firewall address-list find where list=HONEYPOT-INTERNO]]
:local aC2  [:len [/ip firewall address-list find where list=CPE-MIRAI-C2]]
:local aIn  [:len [/ip firewall address-list find where list=EVG-INTERNAS]]

:log warning ("EVG-FW2026 v7.14: REGLAS | IN=" . $rIn . " FWD=" . $rFw . " OUT=" . $rOut . " SYN=" . $rSyn . " EGRESS-BF=" . $rBf . " RAW=" . $rRaw . " V6f=" . $rV6f . " V6r=" . $rV6r)
:log warning ("EVG-FW2026 v7.14: ENTORNO | LAN=" . $nL . " WAN=" . $nW . " | drops activos en forward=" . $dAct . " | CPE-QUARANTINE=" . $aQ . " HONEYPOT=" . $aHp . " C2-Mirai=" . $aC2 . " rangos-internos=" . ($aIn - 1))
:log warning "EVG-FW2026: APLICACION COMPLETADA (v7.14). Revisar: /log print where message~\"EVG-AUDIT\""

# ============================================================================
# NOTA-LAN: SI LOS CLIENTES ENTRAN POR VLANs
# ============================================================================
# La SECCION 6B depende de in-interface-list=LAN. Si esta vacia, esas
# reglas cuentan CERO y parece que la red esta limpia.
#
# :foreach v in=[/interface vlan find] do={
#   :local vN [/interface vlan get $v name]
#   :local vP [/interface vlan get $v interface]
#   :if ([:len [/interface list member find where list="WAN" and interface=$vP]] = 0) do={
#     :do { /interface list member add list=LAN interface=$vN comment="EVG-FW2026 | auto" } on-error={}
#   } else={
#     :log warning ("EVG-FW2026: VLAN omitida por colgar de WAN: " . $vN)
#   }
# }

# ============================================================================
# CASO HAJIME / elf.mirai  ·  agosto 2026, INTEDCOL   [NEW-04] [NEW-05]
# ============================================================================
#  COMO EMPEZO
#    Spamhaus listo dos publicas por elf.mirai. El reporte traia una sola
#    firma util: conexion TCP saliente al puerto 6969.
#
#  QUE SE ENCONTRO
#    En 26 horas, 16 equipos en diez segmentos distintos y con diez
#    fabricantes distintos. No era un modelo defectuoso: era la exposicion.
#
#    Seis reglas dst-nat abrian servicios de administracion a todo internet
#    sin src-address-list. Y en TRES subredes habia un equipo expuesto y un
#    infectado vecino -- el malware entraba por el expuesto y escaneaba su
#    propia subred.
#
#  COMO SE INVESTIGA
#    1. /log print where message~"MIRAI-C2"
#       da la IP interna real, la MAC y la VLAN
#    2. /ip firewall address-list print where list=CPE-MIRAI-C2
#    3. /log print where message~"EVG-EXPOSICION"
#       las reglas dst-nat abiertas y el cruce con los infectados
#    4. /ip arp print where address="<ip>"
#       la MAC dice el fabricante; el OUI repetido delata un modelo comun
#
#  QUE SE HACE, EN ORDEN
#    1. El drop del 6969 detiene la emision. Sin eso el XBL no expira por
#       mas que limpies los equipos.
#    2. Cerrar los dst-nat expuestos. Sin eso vuelven a entrar en semanas.
#    3. Notificar. Y aqui el canal importa: los residenciales van por
#       visita tecnica, pero los institucionales (alcaldia, salud, colegios)
#       van por oficio formal al responsable de sistemas, y una VLAN de
#       transito va al operador downstream porque el equipo esta en SU red.
#    4. Recien con 48h sin detecciones, pedir el delisting.
#
#  LO QUE NO FUNCIONA
#    Pedir el retiro del XBL antes de cerrar la emision: vuelve a listarse
#    y la segunda vez cuesta mas.
#
# ============================================================================
# CASOS ANDROMEDA / AVALANCHE / NYMAIM
# ============================================================================
#  Andromeda (Gamarue / Wauchos) es malware de WINDOWS, no de TV box. Esta
#  sinkholeada desde el takedown de 2017: el equipo infectado no recibe
#  ordenes de nadie, le habla al vacio. Pero sigue infectado, sigue robando
#  credenciales y sigue delatando tu IP.
#
#  1. Identificar el equipo interno (ya no hay que esperar a Spamhaus):
#       /log print where message~"SINKHOLE-HIT"
#       /ip firewall address-list print where list=CPE-INFECTADO
#
#  2. Cruzar con el suscriptor:
#       /ip arp print where address="<ip-interna>"
#       /ppp active print where address="<ip-interna>"
#
#  3. Si varias publicas del mismo /29 aparecen, averiguar si es UN cliente
#     con varias IP o varios clientes. Andromeda se propaga por red local y
#     por USB: una red interna infectada contagia todo lo que tenga adentro.
#
#  4. El equipo se limpia del lado del suscriptor: antivirus en TODOS los
#     PC, cambio de contraseñas, firmware del router al dia.
#
#  5. Delisting: Spamhaus XBL retira solo cuando deja de ver actividad.
#     Pedirlo ANTES de limpiar solo consigue que vuelva a listarse.
#
#  OJO: circula el consejo de bloquear los rangos de sinkhole. NO lo hagas.
#  El sinkhole es la alarma, no el incendio -- bloquearlo te deja ciego sin
#  curar nada, y esas listas traen rangos que son transito legitimo.
#
# ============================================================================
# CASO SMTP CON HELO pve.homelab.local
# ============================================================================
#  No es malware: es Proxmox, que trae Postfix instalado para notificaciones
#  del sistema y manda por el puerto 25 si no se configura.
#  Solucion: que apunte Postfix a un smarthost autenticado en 587. Asi el
#  bloqueo del 25 no le afecta y sus notificaciones siguen llegando.
#
# ============================================================================
# CHECKLIST POST-DEPLOY
# ============================================================================
#   A LOS 5 MINUTOS:
#   [ ] /log print where message~"EVG-AUDIT"
#         -> si sale alguna FALLA, corregirla ANTES de seguir
#   [ ] /ip firewall filter print stats where comment~"EVG-FW2026"
#   [ ] /routing bgp session print          (todas established)
#   [ ] /ppp active print count-only        (sin caida de sesiones)
#   [ ] /ip firewall connection tracking print   (udp-timeout en 10s)
#   [ ] /ip route print where check-gateway
#         -> TODAS deben seguir activas. Si alguna se cae, revisar la
#            lista GATEWAYS:
#              /ip firewall address-list print where list=GATEWAYS
#            Debe tener los gateways de tus WAN, no solo el placeholder.
#   [ ] /log print where message~"gateway"
#         -> no debe haber mensajes de gateway caido tras aplicar
#
#   A LAS 24-48 HORAS:
#   [ ] /ip firewall address-list print where list=CPE-INFECTADO
#         -> CONFIRMADOS. Estos no son heuristica.
#   [ ] /ip firewall address-list print where list=CPE-BRUTEFORCE
#         -> con v7.6 esta lista se llenaba de clientes SANOS. Si ahora
#            son pocos y consistentes, el FIX-33 funciono.
#   [ ] /ip firewall address-list print where list=CPE-IOT-PROPAGA
#   [ ] /ip firewall address-list print where list=CPE-SQL-SALIENTE
#         -> revisar ANTES de activar OPT-SQL
#   [ ] /ip firewall address-list print count-only where list=CENSO-DOT
#         -> cuantos clientes usan DoT, para saber a cuantos afectaria
#            activar OPT-DOT
#   [ ] /log print where message~"EVG-PROXY"
#   [ ] /ip firewall address-list print where list=CPE-MIRAI-C2
#         -> C2 de Mirai/Hajime (48101/58455). Confirmados, sin heuristica.
#   [ ] /ip firewall address-list print where list=CPE-MIRAI-SOSPECHA
#         -> [FP-01] emisiones al 6969: Hajime O tracker BitTorrent. REVISAR,
#            no es confirmado. EVG-CALIBRA lo escala solo si ademas aparece
#            en una señal dura.
#   [ ] /ip firewall address-list print where list=CPE-IOT-LATERAL
#         -> escaneo ENTRE clientes. El borde normalmente no lo ve.
#   [ ] /log print where message~"EVG-CALIBRA"
#         -> [NEW-09] que umbral de conexiones aprendio, proxies y DoT.
#   [ ] /ip firewall filter print where comment~"DETECTA exceso"
#         -> el connection-limit debe reflejar el valor autocalibrado.
#   [ ] /ip firewall address-list print count-only where list=EVG-NO-AUTOBLOCK
#         -> [FP-03] union de infra exenta de autobloqueo (>1 = poblada).
#   [ ] /log print where message~"EVG-RBL"
#         -> si alguna publica esta en lista negra, y en cual
#   [ ] /ip firewall address-list print where list=EVG-RBL-LISTADA
#   [ ] /log print where message~"EVG-EXPOSICION"
#         -> las reglas dst-nat abiertas a todo internet, y el cruce con
#            los infectados. AQUI ESTA LA VIA DE ENTRADA.
#   [ ] /ip firewall address-list print where list=HONEYPOT-INTERNO
#         -> [FIX-43] las dark-IP elegidas solas. Si solo esta el
#            placeholder 127.0.0.1, revisar el log de EVG-DESCUBRE.
#
#   ACTIVAR OPT- DE A UNO POR SEMANA:
#     /ip firewall filter enable [find comment~"OPT-IOT"]
#   Si entran tickets, se desactiva y ya se sabe cual fue.
#   NUNCA varios a la vez.
#
# ============================================================================
# LO QUE ESTE FIREWALL NO RESUELVE
# ============================================================================
#  Contener no es curar. El equipo infectado sigue infectado, y muchas TV
#  box vienen comprometidas de fabrica: ni el reset alcanza, hay que
#  cambiarlas. Eso es del lado del suscriptor.
#  El firewall te da tiempo, evidencia, y la lista de a quien llamar.
#
#  Suscribir el ASN de cada cliente a los reportes diarios gratuitos de
#  Shadowserver:
#    shadowserver.org/what-we-do/network-reporting/get-reports/
# ============================================================================
