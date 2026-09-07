# EVG-FW2026 — Mejoras v7.13 sobre v7.12

Plantilla de firewall **defensivo** para borde ISP en RouterOS 7.x. Detecta y
mitiga tráfico de botnet (Mirai/Hajime), protege los CPE, audita la exposición
por `dst-nat` y consulta las listas negras (RBL) de las IP públicas del propio
router.

Esta revisión **no cambia la arquitectura ni el estilo**: corrige cuatro bugs
de lógica donde una función quedaba silenciosamente inactiva o hacía lo
contrario de lo esperado. Todos los cambios están marcados en el script con su
etiqueta `[FIX-xx]`.

## Los cuatro arreglos

### [FIX-43] Los honeypot autodescubiertos nunca se usaban
La regla de detección `6B.2` matchea `dst-address-list=HONEYPOT-INTERNO`, pero
`EVG-DESCUBRE` (PASO 7B) poblaba una lista con **otro nombre** (`EVG-HONEYPOT`).
Las dark-IP que el router elegía solo jamás llegaban a la regla, así que la
mejor detección sin falsos positivos estaba, de hecho, **apagada**. Solo
funcionaban los honeypot cargados a mano en la Sección 2.10.

- Todo unificado a `HONEYPOT-INTERNO` (PASO 7B add/remove, PASO 7 "listas que
  deben existir", el RESUMEN y el checklist post-deploy).
- Nueva verificación en `EVG-AUDIT` que avisa si vuelven a aparecer entradas en
  la lista obsoleta `EVG-HONEYPOT`.

### [FIX-44] La protección brute-force de PPTP era código muerto
La Sección 5.6 aceptaba `tcp/1723` **antes** del staging de la 5.7c. En
RouterOS gana la primera regla que hace match: el `accept` de 5.6
cortocircuitaba y las cinco reglas de conteo/baneo de PPTP nunca veían una
conexión nueva. El puerto quedaba abierto a diccionario sin ningún límite.

- Se quitó el `accept tcp/1723` de la 5.6 (el GRE de datos sigue ahí).
- El bloque 5.7c ahora termina con su propio `accept`, igual que el patrón ya
  probado de SSH y Winbox.

### [FIX-45] `EVG-DESCUBRE` vaciaba WAN/LAN ante un fallo transitorio
El PASO 1 borraba **todos** los miembros `EVG-AUTO` de WAN y LAN al inicio y
recién después recalculaba. Si en ese instante no había ruta por defecto (flap
del uplink, BGP reconvergiendo), la lista WAN quedaba **vacía** hasta el
siguiente ciclo — 30 minutos con anti-spoofing, los drops de borde y el DROP
FINAL de INPUT contando cero. El router quedaba expuesto por una caída
momentánea.

- Ahora se calcula primero y **solo se reemplaza** la lista si la detección
  trajo al menos una interfaz; si viene vacía, se **conserva** la lista actual y
  se registra el error.
- El PASO 2 reconoce como WAN lo que ya esté en la interface-list WAN (no solo
  lo detectado en el ciclo), para no reclasificar la WAN como LAN.

### [FIX-46] IPv6 bloqueaba el 7547 contradiciendo la decisión de IPv4
Toda la lógica IPv4 deja el `7547` (TR-069) **fuera** del bloqueo a propósito,
para no romper el aprovisionamiento por ACS de toda la base. La Sección 10 sí lo
dropeaba hacia clientes en IPv6, cortando la gestión si el ACS es alcanzable por
IPv6.

- El `7547` sale del drop activo IPv6 y queda como `OPT-V6-7547` **deshabilitado**,
  para que lo active solo quien **no** use ACS sobre IPv6.

## Nota de mantenimiento (no es un bug)
Spamhaus está migrando el formato DROP de texto plano a JSON. Si `drop.txt` deja
de responder, `EVG-UPDATE-SPAMHAUS` ya **conserva la lista previa** y lo
registra (no la vacía). Cuando haga falta, migrar el parser a
`https://www.spamhaus.org/drop/drop_v4.json`. Se dejó anotado en la Sección 9.2.

## Aplicación
Igual que antes (ver cabecera del `.rsc`, "APLICACIÓN SEGURA"):
1. `/export file=antes-v713`
2. Pegar el script y activar el bypass:
   `/ip firewall filter enable [find where comment~"BYPASS"]`
3. Verificar acceso (el auto-off apaga el bypass en 5 min).
4. A los 5 minutos: `/log print where message~"EVG-AUDIT"`
