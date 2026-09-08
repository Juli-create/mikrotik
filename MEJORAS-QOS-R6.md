# EVG-QOS2026 — Revisión R6 sobre R5

Archivo: `EVG-QOS2026-R6.rsc`. Misma arquitectura, mismas clases y el mismo tag
de idempotencia (`EVG-QOS2026`) que R5: se puede reaplicar encima y borra R2…R5.

Los cuatro primeros puntos son **bugs**, no mejoras opinables. Los tres
siguientes son supuestos de R5 que no se sostienen contra la implementación real
de CAKE ni contra el flujo de paquetes de RouterOS.

---

## Bugs

### [R6-01] `cake-nat=si` aborta el import — y deja el router sin QoS
R5 declara `:global EVGNAT "no"` y documenta que hay que ponerlo en `"si"`
cuando una cola agrupa varios clientes. Ese valor se pasa **tal cual** a
`cake-nat=$EVGNAT`, y RouterOS espera `yes`/`no`.

Con `"si"` el `add` del queue type falla. Como `/import` corta en el primer
error y la limpieza idempotente ya corrió (Sección 1), el equipo queda **sin
QoS**: justo el único cambio que R5 le pide al operador es el que rompe.

R6 traduce `si|no|yes|no` y agrega `EVGNAT="auto"`: mira si hay colas cuyo
target es una red y si hay `src-nat`/masquerade, y decide.

### [R6-02] Un solo error tira todo el script
Mismo problema en general: cualquier propiedad que el build no soporte
(`tls-host` en `/ipv6 firewall mangle`, `interface-list` en `/ppp profile`,
`connection-rate`) aborta el import después de la limpieza.

R6 envuelve cada bloque en `:do{}on-error={}`, cuenta las fallas en `$EVGERR` y
cierra con una línea que dice cuántos bloques fallaron. Peor caso: se pierde un
bloque, no la configuración entera.

### [R6-03] Autodescubrimiento de WAN: PPPoE-client y ECMP se perdían
R5 exige que `immediate-gw` contenga `%` para extraer la interfaz:

- En una ruta punto a punto (`pppoe-out1`, `l2tp-out1`, WireGuard) el campo es
  **sólo el nombre de la interfaz**, sin `%` → ese uplink nunca entraba a WAN.
- Con **ECMP** el campo trae varios next-hop separados por coma; R5 tomaba desde
  el primer `%` **hasta el final de la cadena** → nombre inexistente, se perdían
  los dos uplinks.

R6 parte por comas y trata el `%` como opcional. Además descubre WAN por la ruta
por defecto IPv6 (`::/0`).

### [R6-04] `$EVGELEBYTES` nunca se usaba
La variable está declarada y documentada, pero las tres reglas de elefante
llevan `250000000` escrito a mano. Cambiar la variable no cambiaba nada.

---

## Supuestos de R5 que no se sostienen

### [R6-05] `cake-wash`: R5 confunde dos lavados distintos
R5 pone `cake-wash=no` y lo justifica con *"el wash lo hacemos nosotros en
mangle"*. Son cosas distintas:

| | Qué hace | Dónde |
|---|---|---|
| wash de mangle | borra el DSCP que **trae** el paquete | ingreso (prerouting) |
| `cake-wash` | CAKE elige el tin y **después** pone el DSCP en 0 | egreso (dequeue) |

Con `cake-wash=no` el DSCP que ponemos nosotros **sale del router**:

- **hacia el cliente** → el CPE lo mapea a WMM. `AF11` (YouTube) cae en `AC_BK`,
  y `CS1` (bulk) también: en un WiFi cargado el video queda detrás de todo. Es
  una causa bastante más probable de *"se pega"* que la regla de elefante.
- **hacia el upstream** → le exportamos nuestra política interna a un tránsito
  que puede tener su propia policía por DSCP.

R6 usa `cake-wash=yes` por defecto (`$EVGWASH`). La clasificación no cambia:
CAKE ya eligió el tin antes de lavar.

**Trampa relacionada, documentada en el script:** no "arreglar" la fuga de DSCP
con un `change-dscp` en `postrouting`. El HTB/cola corre **después** de
postrouting, así que ese lavado le borraría el DSCP a CAKE antes de que lo lea y
rompería toda la clasificación de subida.

### [R6-06] El mapeo `CS1 → tin 0` depende de la versión de CAKE
La tabla que R5 da por cierta es la de cake 2017 (`diffserv8[8] = 0`). En cake
moderno esa fila cambió con RFC 8622 (LE):

```
cake viejo:  diffserv8[8] = 0   -> CS1 al tin 0 (Background)
cake nuevo:  diffserv8[1] = 0   -> LE (DSCP 1) al tin 0
             diffserv8[8] = 1   -> CS1 al tin 1, junto con AF1x
```

Según el build, `BULK` (CS1) cae en tin 0 **o comparte tin con `STREAMING`**
(AF11). No se arregla poniendo DSCP 1: en la tabla vieja el DSCP 1 va al **tin 5**
(Interactive Shell), o sea las actualizaciones subirían a la clase de latencia
crítica.

R6 deja CS1, expone `$EVGDSCPBULK` y agrega al script una **prueba empírica**
para saber qué tabla tiene tu equipo (sección "COMPROBACIÓN DE TIN").

### [R6-07] Se evaluaban ~50 reglas por paquete
Es el cambio que más se nota en un nodo cargado, y va directo al problema que R5
describe ("80 % de CPU con ~670 sesiones"):

- En R5, **todo** paquete de cliente recorre las ~45 reglas de `mark-connection`
  hasta que alguna matchea. Los paquetes de tráfico ya establecido —la enorme
  mayoría— las recorren **todas** para terminar descartados por
  `connection-state=new`.
- En raw, ~60 reglas `tls-host` evaluadas por cada paquete, sea o no 443.

R6 mete todo en **cadenas propias** con una sola regla de entrada:

| Cadena | Regla de entrada |
|---|---|
| `EVG-SNI` (raw) | `tcp dst-port=443,80` desde clientes |
| `EVG-SNILIVE` (mangle) | `tcp/443` + `connection-bytes=0-20000` |
| `EVG-MARK` (mangle) | `connection-state=new` + interface-list de clientes |

Un paquete de una descarga en curso pasa de ~45 evaluaciones a 3. El resultado
es idéntico; cambia el costo.

Además, el modo `EVGCPU="bajo"` ahora recorta las listas SNI largas (sociales y
BULK): ahí está el ahorro real, no en `diffserv4` (elegir el tin es una lectura
de tabla, no cuesta).

---

## Mejoras

### [R6-08] Los rangos anchos de gaming ya no envenenan tin 5 / tin 6
R5 advierte del riesgo y no hace nada. Los rangos `5000-5500` (LoL),
`7000-7999` (Free Fire), `9000-9100`, `27000-27050` y `16000-17000` (RTP)
atrapan tráfico que no es una partida ni una llamada — y en CAKE eso no es
neutro: los tines altos tienen umbral **bajo**, así que un flujo pesado ahí se
autocastiga y de paso empuja a la voz real.

R6 desasciende por **tasa** (`connection-rate`), no por bytes acumulados:

- una partida son decenas de kbps; una llamada RTP, ~100 kbps
- una descarga por el mismo puerto son megabits sostenidos

Como la tasa se mide sobre los últimos segundos, es **reversible**: si el flujo
baja, vuelve solo a su clase. Es exactamente lo contrario de la regla de
elefante. Variables `$EVGGAMERATE` (5M) y `$EVGEFRATE` (3M); `"0"` desactiva.

### [R6-09] Guardas que faltaban y apagan el QoS sin avisar
- **conntrack en `no`** → todas las reglas `connection-mark` son papel pintado.
  Aborta.
- **bridge con `use-ip-firewall=no`** → el tráfico puenteado entre clientes del
  mismo bridge no pasa por mangle. Avisa (para internet no cambia nada).
- **`BYPASS-RAW` de EVG-FW2026 habilitado** → corta el raw y las listas por SNI
  dejan de poblarse. Avisa.

### [R6-10] IPv6 se clasificaba pero no se conformaba
R5 hace un espejo completo en IPv6. Pero la cola simple dinámica de PPP tiene
como target la **IP v4** del cliente: el tráfico IPv6 **no entra a esa cola**. Se
clasifica con todo detalle tráfico que después sale **sin shaping** — el cliente
con IPv6 no tiene plan, y el QoS pierde el control del bufferbloat justo en el
tráfico que más crece.

R6 lo detecta (hay IPv6 o DHCPv6-PD y ninguna cola con target IPv6) y lo grita en
el log y en el reporte, con las dos salidas posibles documentadas al final del
`.rsc` (colas estáticas con doble target, o pasar a queue tree con packet-mark).
No lo "arregla" solo: es un cambio de arquitectura, no un parche.

### Resto
- **[R6-11]** Reglas de `chain=output` acotadas con `out-interface-list`: R5
  marcaba EF también el DNS/ICMP que el router manda **al upstream**. Se agregan
  las que faltaban (DNS TCP v6, DoT, Winbox saliente).
- **[R6-12]** La limpieza ahora borra `/ipv6 firewall address-list` y las
  entradas **dinámicas** aprendidas por SNI (no llevan comentario, así que el
  borrado por tag no las veía: quedaban IPs clasificando con el criterio viejo
  hasta 12 h).
- **[R6-13]** Nombres de address-list sin espacios (`HBO MAX` → `HBO-MAX`, etc.).
  Un nombre con espacio es el origen típico del mismo bug que R5 arregló en el
  queue type. La limpieza contempla los nombres viejos.
- **[R6-14]** `/ppp profile queue-type`: R5 escribe `"EVG-CAKE2026/EVG-CAKE2026"`,
  que es el formato **par** de `/queue simple`. R6 intenta primero el nombre
  simple y sólo si falla prueba el par.
- **[R6-15]** `EVG-QOS-COLAS` también engancha los **ppp profile** nuevos (el
  facturador crea perfiles, no sólo colas). `EVG-QOS-REPORT` agrega: contador de
  la regla GATE (si está en cero no se clasifica nada), coherencia
  overhead/MPU, colas sin `max-limit`, colas que no usan CAKE, IPv6 sin cola y
  cuántos paquetes desascendió [R6-08].
- **[R6-16]** `$EVGPURGA`: purga automática y **selectiva** de conntrack al
  terminar (sólo lo que no tiene marca; no corta descargas ya clasificadas).
- Los scripts se crean **sin `owner=admin`**: en un equipo donde ese usuario fue
  renombrado por política, el `add` falla y (por [R6-02]) se perdía todo lo que
  venía después.

---

## Lo que R5 ya tenía bien y R6 no toca

- Autodescubrimiento con borrado selectivo por tag `EVG-QOS2026-AUTO`.
- La fórmula de overhead y las dos escuelas (18/38) con su MPU (64/84),
  incluida la corrección de la matriz de R4.
- Speedtest en **tin 2** y no en tin 6 (en tin 6 el umbral es bajo y un test que
  satura se auto-degrada).
- Reclasificación por SNI en vivo para el primer flujo.
- Regla de elefante creada pero deshabilitada.
- `5060/TCP` fuera del match de speedtest (choca con SIP sobre TCP).
- Redes sociales en tin 2 junto con la web.
- `fast.com` sin priorizar (comparte infra con Netflix Open Connect).

---

## Nota honesta de verificación

No pude probar esto en un equipo real desde acá. Lo que sí está verificado es la
consistencia interna: llaves y paréntesis balanceados, comillas pares, ninguna
variable declarada y no usada, ningún `find` sin ruta dentro de los scripts
almacenados, y ningún nombre de cadena que choque con `EVG-FW2026`
(`SYN-PROT`, `EVG-EGRESS-BF`).

Dos construcciones dependen del build y por eso van envueltas en
`:do{}on-error={}` con aviso al log:

1. `tls-host` en `/ipv6 firewall mangle` y `/ipv6 firewall raw`.
2. `connection-rate` en `change-dscp` ([R6-08]).

Si alguna falla, el log lo dice y el resto del QoS queda aplicado.

**Procedimiento sugerido:** `/export file=antes-qos`, importar, mirar
`/log print where message~"EVG-QOS2026"` y confirmar que la última línea dice
**0 bloques fallados**; después `/ip firewall mangle print stats where
comment~"GATE -> cadena EVG-MARK"` — si ese contador está en cero, la
interface-list de clientes está mal y nada se está clasificando.
