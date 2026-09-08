# tools/ — Validación de IPs en listas negras y desliste

## `rbl-check.py`

Consulta una o varias IPv4 contra 18 DNSBL públicas y, por cada listado,
imprime el código de retorno y el enlace de desliste que corresponde.

Es la misma consulta DNS que hace la web de MXToolbox por detrás: se invierte
la IP y se pregunta `A` a `<ip-invertida>.<zona>`. Una respuesta `127.0.0.x`
significa listada; `NXDOMAIN` significa limpia.

Solo necesita Python 3 y salida DNS. Sin dependencias, sin API key.

### Uso

```sh
./tools/rbl-check.py 203.0.113.7 203.0.113.8
./tools/rbl-check.py --file ips.txt      # extrae las IPv4 del texto
cat reclamo.txt | ./tools/rbl-check.py   # ídem por stdin
./tools/rbl-check.py --json 203.0.113.7  # para automatizar
./tools/rbl-check.py --block 203.0.113.7 # + barrido del /24 (ver abajo)
```

Acepta texto libre: saca las IPv4 con regex, descarta duplicados, privadas
(RFC1918/CGNAT), loopback, link-local, multicast y reservadas, y avisa de las
malformadas.

Código de salida: `0` si ninguna IP está listada, `1` si hay al menos un
listado, `2` si no encontró ninguna IP en la entrada.

### Qué revisa además del listado

- **Motivo del listado.** Lee el registro `TXT` de cada lista, que es donde
  publican la razón concreta (`Open HTTP proxy`, `Automated dictionary
  attacks`, `Unknown worm or spambot`). Sin esto sólo se ve un código
  `127.0.0.x` que no dice qué hay que arreglar. Se consulta con un paquete
  DNS armado a mano: `socket` de la stdlib sólo trae registros `A`.
- **ASN, prefijo y país** del rango, vía Team Cymru por DNS (`origin.asn.
  cymru.com`). Sirve para saber a quién le corresponde el desliste sin salida
  HTTP hacia un WHOIS.
- **PTR (rDNS).** Si la IP no tiene PTR lo marca. Es la causa más frecuente
  de rechazo en Gmail/Outlook y de que un rango de ISP termine listado.

### `--block`: distinguir un listado propio de una clasificación del rango

`--block` barre las 254 IPs del `/24` contra las 18 listas y cuenta cuántas
figuran en cada una.

```
dnsbl.spfbl.net       248/254  clasificacion del BLOQUE, no de la IP
dnsbl.dronebl.org      27/254  listado por IP
```

Es la diferencia que decide qué hacer. Una lista que marca **casi todo el
`/24`** no está reportando abuso de tu IP: está clasificando el rango entero
(residencial, dinámico, "no es servidor de correo"). Pedir el desliste
individual ahí no sirve — se corrige con el dueño del bloque. Una lista que
marca **unas pocas IPs** sí es un listado propio, con una causa concreta que
hay que cortar.

El barrido son ~4.500 consultas DNS; bajo límite de tasa del resolver algunas
se pierden y los conteos varían en unas pocas unidades entre corridas. Para
decidir "bloque vs. IP" alcanza y sobra.

### Listas consultadas

SpamCop · Barracuda · PSBL · UCEPROTECT L1/L2/L3 · s5h.net · Mailspike BL y
Rep · GBUdb Truncate · DroneBL · InterServer · HostKarma · SEM BL ·
SEM Backscatter · SPFBL · Spamlookup BSB · 0SPAM

Los códigos que **no** son un listado están filtrados por zona: HostKarma
`127.0.0.1` es whitelist y `127.0.0.3/4/5` son amarillo/marrón/NOBL;
`z.mailspike.net` `127.0.0.14`–`.20` es reputación neutra o buena.

### Listas que este script NO puede consultar

**Spamhaus** (ZEN = SBL + XBL + PBL) y **SpamRats** rechazan las consultas
que llegan desde resolvers públicos (8.8.8.8, 1.1.1.1) y desde rangos de
nube. Devuelven `NXDOMAIN` o un código de error aunque la IP esté listada,
así que un "limpia" del script **no dice nada** sobre Spamhaus.

Dos formas de cubrirlas:

1. **A mano.** El script imprime el enlace directo por IP
   (`check.spamhaus.org`, `spamrats.com`, MXToolbox, Talos).
2. **Con resolver propio.** Corriendo el script desde un host con un resolver
   recursivo propio (unbound/bind en la red, no un DNS público), las zonas de
   Spamhaus responden y se pueden agregar a `ZONES` en el script. Para volumen
   alto Spamhaus exige el DQS (clave gratuita hasta cierto tráfico) y la zona
   pasa a ser `<clave>.zen.dq.spamhaus.net`.

Tampoco se consultan por DNS **Microsoft SNDS** ni **Google Postmaster**:
requieren cuenta con el rango verificado. Vale la pena darlos de alta una vez.

---

## Desliste: procedimiento

El desliste **no se automatiza desde acá**. Cada lista pide CAPTCHA,
confirmación por correo a una dirección del rango (`abuse@`, la del WHOIS) o
cuenta propia, y varias sólo aceptan el pedido del responsable del bloque.
Este repo llega hasta la validación y los enlaces; el formulario lo manda el
operador del AS.

### Antes de pedir nada

Un desliste sin arreglar la causa vuelve a listar en horas y endurece el
próximo pedido (UCEPROTECT y SpamCop penalizan la reincidencia).

1. **Encontrar el origen.** En este firewall, las listas `CPE-INFECTADO`,
   `CPE-MIRAI-SOSPECHA` y las detecciones de SMTP saliente de
   `EVG-FW2026-v7.14.rsc` señalan qué CPE está emitiendo. Ver también
   `MEJORAS-v7.14.md`.
2. **Cortar la emisión.** Bloquear 25/tcp saliente para clientes que no sean
   servidores de correo declarados, aislar el CPE infectado, cerrar el relay
   abierto o la cuenta SMTP comprometida.
3. **Higiene del correo saliente.** PTR que resuelva de vuelta a la misma IP,
   SPF, DKIM y DMARC del dominio que envía, y HELO que coincida con el PTR.
4. **Recién ahí**, pedir el desliste.

### Particularidades por lista

| Lista | Cómo sale |
|---|---|
| **Spamhaus PBL** | Es rango dinámico declarado por el propio ISP. Si son IPs de servidor mal clasificadas, el que corrige es el ISP dueño del rango, no el cliente. |
| **Spamhaus SBL/XBL** | XBL sale sola al cortar la emisión (reevalúa en horas). SBL es manual y pide evidencia de la corrección. |
| **UCEPROTECT L2** | Lista el `/24` entero, no la IP. Expira sola a los 7 días sin abusos. El "express delisting" es pago y no arregla la causa: conviene esperar. |
| **UCEPROTECT L3** | Lista el ASN entero. No se desliste IP por IP. |
| **SpamCop** | Expira sola a las 24 h del último informe. |
| **Barracuda / SEM / SPFBL / PSBL** | Formulario con correo de contacto del rango. |
| **SEM Backscatter** | Listada por rebotar bounces a remitentes falsos. Hay que pasar a rechazar en la sesión SMTP antes de pedir el desliste. |

### Datos que piden los formularios

- La IP y el bloque (`/24` o el que figure en el WHOIS).
- Correo de contacto que esté en el WHOIS o en `abuse@` del dominio.
- Qué causó el abuso y qué se hizo para cortarlo, concreto: "CPE con Mirai en
  198.51.100.x, aislado el <fecha>; 25/tcp saliente bloqueado para clientes
  residenciales; SMTP autenticado con límite de tasa por cuenta".
- Fecha y hora aproximadas de la corrección.

Una plantilla que sirve para casi todas:

```
IP: 203.0.113.7 (bloque 203.0.113.0/24, AS64500)
Contacto: abuse@ejemplo.net

Causa del listado: equipo de cliente comprometido emitiendo SMTP directo
al puerto 25 desde el rango residencial.

Corrección aplicada el 2026-09-05:
 - CPE identificado y puesto en cuarentena.
 - Bloqueo de 25/tcp saliente para todo el rango residencial; el correo
   de clientes pasa por el relay autenticado con límite de tasa.
 - PTR publicado y verificado; SPF/DKIM/DMARC en el dominio emisor.

Solicito la revisión del listado. Quedo a disposición para cualquier
evidencia adicional.
```
