# EVG-FW2026 — Mejoras v7.14 sobre v7.13

Dos objetivos: **(1) que las detecciones no marquen tráfico legítimo** y
**(2) que los umbrales de "tráfico válido" se autoconfiguren** con lo que es
normal en *esta* red, en lugar de un número fijo.

Todos los cambios están marcados en el `.rsc` con su etiqueta (`[FP-xx]`,
`[NEW-09]`) y la arquitectura, el estilo y la numeración de tu script se
mantienen.

## Menos falsos positivos

### [FP-01] El 6969 ya no es "infección confirmada"
El 6969 es a la vez la firma de Hajime **y** un puerto legítimo de tracker
BitTorrent. En v7.13 caía en `CPE-INFECTADO` junto al sinkhole y el honeypot,
ensuciando la lista que el script jura que "no es heurística".

- `48101` y `58455` (exclusivos de Mirai) → siguen **CONFIRMADOS**.
- `6969` solo → `CPE-MIRAI-SOSPECHA` (para revisar), **no** `CPE-INFECTADO`.
- El **drop** del 6969 se mantiene (frena la emisión y evita el listado XBL;
  romper un tracker BitTorrent es un daño menor).
- `EVG-CALIBRA` **escala** un 6969 a confirmado solo si el mismo equipo aparece
  además en una señal dura (sinkhole/honeypot, propagación IoT o lateral).

### [FP-02] DoT: se aprende qué resolver es legítimo por consenso
La lista `DNS-OK` era corta y un cliente con un resolver DoT válido pero no
listado caía en `CPE-DOT-RARO`. Un C2 lo usa **un** bot; un resolver legítimo
lo usan **muchos** clientes.

- Se amplió `DNS-OK` (Cloudflare families, Quad9 ECS, Mullvad, dns0.eu, ControlD).
- `EVG-CALIBRA` promueve a `DNS-OK` (con timeout) cualquier destino `:853` usado
  por **≥ `EVGDOTMINCLIENTES`** clientes distintos.

### [FP-03] La infraestructura propia no se autobloquea por spoofing
El origen de un paquete se falsifica: un paquete con `src=8.8.8.8` al 445 metía
tu propio resolver/gateway/peer en `PORT-SCAN`.

- Nueva lista `EVG-NO-AUTOBLOCK` = unión de `GATEWAYS + BGP-PEERS + DNS-OK +
  IP-PUBLICA + WAN-PRIVADA` (la arma `EVG-CALIBRA`).
- Los tres detectores de INPUT (honeypot TCP/UDP y PSD) llevan
  `src-address-list=!EVG-NO-AUTOBLOCK`. Con la lista vacía se comportan igual
  que antes (nadie exento), así que el cambio es seguro por defecto.

### [FP-04] El detector de proxy ya no confunde videollamadas
Una videollamada (Zoom/Meet/WhatsApp) es **un** flujo grande y simétrico — y en
v7.13 se marcaba como proxy. Un proxy real relaya **muchos** flujos simétricos.

- Ahora se cuentan los flujos grandes y simétricos **por equipo** y solo se
  marca al que tiene **≥ `EVGPROXYMINFLOWS`** (default 4).
- Además sube el mínimo de bytes (`EVGPROXYMINMB`, 40 MB) y aprieta el factor
  (`EVGPROXYFACTOR`, 2 = ratio > 0.5).

## Autoconfiguración — `EVG-CALIBRA` (Sección 9.9, reemplaza a `EVG-PROXY`)

Todos los umbrales que afectan a clientes son ahora **variables globales con
piso y techo** (arriba del script, junto a `EVGWINBOX`). `EVG-CALIBRA` corre
cada hora y, en **una sola pasada** por la tabla de conexiones:

1. **Umbral de conexiones concurrentes (6B.5):** mide el cliente más ocupado y
   fija el umbral en **2×** eso, acotado a `[EVGCONNFLOORMIN, EVGCONNFLOORMAX]`
   (400–4000), con **histéresis del 15 %** para no oscilar. Lee el valor actual
   **de la regla** (que persiste en config), así sobrevive a un reboot.
2. **Proxies** por simetría multi-flujo (FP-04).
3. **DoT legítimo** por consenso (FP-02).
4. **`EVG-NO-AUTOBLOCK`** = unión de infra de confianza (FP-03).
5. **Corroboración del 6969** (FP-01).

### Por qué es seguro
- El **drop** de conexiones (6B.5) sigue **deshabilitado** (`OPT-CONEXIONES`),
  así que autoajustar ese umbral solo cambia una lista de detección: **nunca
  corta a un cliente.**
- Todo queda **acotado por piso/techo**: un bug no puede poner el umbral en 0
  (bloquear todo) ni en infinito (no detectar nada). `EVG-AUDIT` verifica además
  que el valor quede en `[100..8000]` y que `EVG-NO-AUTOBLOCK` no contenga
  `0.0.0.0/0`.
- **Costo acotado:** si la tabla supera `EVGCONNMAXSCAN` (60000) se omite el
  conteo pesado y solo se avisa, para no clavar la CPU.

### Si preferís fijar los límites a mano
Poné el valor en la global correspondiente y desactivá el scheduler
`EVG-CALIBRA`. `EVG-CALIBRA` siempre respeta el piso y el techo.

## Nota / advertencia honesta
El bloque de conteo por conexión de `EVG-CALIBRA` usa **arrays asociativos** de
RouterOS (`($arr->clave)` y `:foreach k,v in=...`), que funcionan en RouterOS 7
pero **no pude probarlos en un equipo real** desde aquí. Aplicá con el
procedimiento seguro de la cabecera (export, BYPASS, revisar `EVG-AUDIT` a los 5
min) y mirá `/log print where message~"EVG-CALIBRA"`. Si tu versión de ROS se
queja del conteo, se puede simplificar a una variante sin arrays asociativos.

## Qué revisar tras aplicar
```
/log print where message~"EVG-CALIBRA"
/ip firewall filter print where comment~"DETECTA exceso"        # umbral aprendido
/ip firewall address-list print where list=CPE-MIRAI-SOSPECHA   # 6969: revisar
/ip firewall address-list print count-only where list=EVG-NO-AUTOBLOCK
/ip firewall address-list print where list=DNS-OK               # incluye EVG-AUTO
```
