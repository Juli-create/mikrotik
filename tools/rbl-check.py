#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rbl-check.py — Valida IPs contra listas negras (DNSBL) y arma el desliste.

Hace por DNS lo mismo que consulta la web de MXToolbox: pregunta a cada DNSBL
por la IP invertida y reporta el codigo de retorno. Para cada listado imprime
la URL de desliste y que hace falta para pedirlo.

Uso:
    ./rbl-check.py 1.2.3.4 5.6.7.8
    ./rbl-check.py --file ips.txt          # extrae las IPs del texto
    cat correo.txt | ./rbl-check.py        # idem por stdin
    ./rbl-check.py --json 1.2.3.4          # salida para automatizar

Salida: 0 si ninguna IP esta listada, 1 si hay al menos un listado.
"""

import argparse
import concurrent.futures as futures
import ipaddress
import json
import random
import re
import socket
import struct
import sys

# --------------------------------------------------------------------------
# Zonas DNSBL.
#
#   zone     : zona a consultar (se antepone la IP invertida)
#   name     : nombre legible
#   delist   : URL del formulario de desliste
#   ignore   : codigos 127.0.0.x que NO son un listado (whitelist/neutral)
#   note     : aclaracion que se imprime junto al listado
#
# Solo se incluyen listas que responden desde un resolver publico. Spamhaus
# (zen/sbl/xbl/pbl) y SpamRats rechazan las consultas que vienen de resolvers
# publicos o de nubes: se consultan aparte (ver MANUAL, abajo).
# --------------------------------------------------------------------------
ZONES = [
    {"zone": "bl.spamcop.net", "name": "SpamCop",
     "delist": "https://www.spamcop.net/bl.shtml"},
    {"zone": "b.barracudacentral.org", "name": "Barracuda",
     "delist": "https://www.barracudacentral.org/rbl/removal-request"},
    {"zone": "psbl.surriel.com", "name": "PSBL",
     "delist": "https://psbl.org/remove"},
    {"zone": "dnsbl-1.uceprotect.net", "name": "UCEPROTECT L1",
     "delist": "https://www.uceprotect.net/en/rblcheck.php"},
    {"zone": "dnsbl-2.uceprotect.net", "name": "UCEPROTECT L2",
     "delist": "https://www.uceprotect.net/en/rblcheck.php",
     "note": "L2 lista el bloque /24 completo, no la IP: expira sola en 7 dias "
             "sin nuevos abusos. El desliste pago no arregla la causa."},
    {"zone": "dnsbl-3.uceprotect.net", "name": "UCEPROTECT L3",
     "delist": "https://www.uceprotect.net/en/rblcheck.php",
     "note": "L3 lista el ASN completo. No se desliste IP por IP."},
    {"zone": "all.s5h.net", "name": "s5h.net",
     "delist": "https://www.usenix.org.uk/content/rbl.html"},
    {"zone": "bl.mailspike.net", "name": "Mailspike BL",
     "delist": "https://mailspike.org/iplookup.html"},
    {"zone": "z.mailspike.net", "name": "Mailspike Rep",
     "delist": "https://mailspike.org/iplookup.html",
     # 127.0.0.14..20 son reputacion neutra o buena
     "ignore": {"127.0.0.14", "127.0.0.15", "127.0.0.16", "127.0.0.17",
                "127.0.0.18", "127.0.0.19", "127.0.0.20"}},
    {"zone": "truncate.gbudb.net", "name": "GBUdb Truncate",
     "delist": "https://www.gbudb.com/truncate/index.jsp"},
    {"zone": "dnsbl.dronebl.org", "name": "DroneBL",
     "delist": "https://dronebl.org/lookup"},
    {"zone": "rbl.interserver.net", "name": "InterServer",
     "delist": "https://rbl.interserver.net/"},
    {"zone": "hostkarma.junkemailfilter.com", "name": "HostKarma",
     "delist": "https://ipadmin.junkemailfilter.com/remove.php",
     # .1 = whitelist, .3 = amarillo, .4 = marron, .5 = NOBL. Solo .2 es negro.
     "ignore": {"127.0.0.1", "127.0.0.3", "127.0.0.4", "127.0.0.5"}},
    {"zone": "bl.spameatingmonkey.net", "name": "SEM BL",
     "delist": "https://spameatingmonkey.com/removal"},
    {"zone": "backscatter.spameatingmonkey.net", "name": "SEM Backscatter",
     "delist": "https://spameatingmonkey.com/removal",
     "note": "Backscatter = el servidor rebota bounces a remitentes falsos. "
             "Arregle el rechazo en SMTP antes de pedir desliste."},
    {"zone": "dnsbl.spfbl.net", "name": "SPFBL",
     "delist": "https://spfbl.net/en/delisting"},
    {"zone": "bsb.spamlookup.net", "name": "Spamlookup BSB",
     "delist": "https://spamlookup.net/"},
    {"zone": "0spam.fusionzero.com", "name": "0SPAM",
     "delist": "https://0spam.fusionzero.com/"},
]

# Listas que hay que mirar a mano: bloquean resolvers publicos/nube (Spamhaus,
# SpamRats) o exigen consulta con clave. Se imprime el enlace directo.
MANUAL = [
    ("Spamhaus ZEN (SBL/XBL/PBL)", "https://check.spamhaus.org/results?query={ip}"),
    ("SpamRats", "https://www.spamrats.com/lookup.php?ip={ip}"),
    ("MXToolbox (vista agregada)", "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip}"),
    ("Cisco Talos", "https://talosintelligence.com/reputation_center/lookup?search={ip}"),
    ("Microsoft/Outlook (SNDS)", "https://sendersupport.olc.protection.outlook.com/snds/"),
    ("Google Postmaster", "https://postmaster.google.com/"),
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# --------------------------------------------------------------------------
# Consulta DNS cruda para registros TXT.
#
# socket.gethostbyname_ex() solo trae registros A, pero el motivo del listado
# viaja en el TXT ("Open HTTP proxy", "Automated dictionary attacks"). Sin
# dnspython en la mayoria de los equipos, se arma el paquete a mano: son 30
# lineas y evita una dependencia.
# --------------------------------------------------------------------------

def _nameservers():
    out = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1 and ":" not in parts[1]:
                        out.append(parts[1])
    except OSError:
        pass
    return out or ["8.8.8.8", "1.1.1.1"]


def _skip_name(data, i):
    """Avanza sobre un nombre DNS (comprimido o no) y devuelve el offset."""
    while True:
        ln = data[i]
        if ln == 0:
            return i + 1
        if ln & 0xC0:          # puntero de compresion: 2 bytes y termina
            return i + 2
        i += ln + 1


def dns_txt(name, timeout=5.0):
    """Devuelve la lista de cadenas TXT de `name`, o [] si no hay o falla."""
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    packet = header + qname + struct.pack(">HH", 16, 1)   # QTYPE=TXT, QCLASS=IN

    for server in _nameservers()[:2]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
        except OSError:
            continue
        finally:
            sock.close()

        if len(data) < 12 or struct.unpack(">H", data[:2])[0] != query_id:
            continue
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return []
        try:
            i = _skip_name(data, 12) + 4          # saltar QNAME + QTYPE/QCLASS
            out = []
            for _ in range(ancount):
                i = _skip_name(data, i)
                rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
                i += 10
                rdata = data[i:i + rdlen]
                i += rdlen
                if rtype == 16:                    # TXT: secuencia de <len><bytes>
                    j, chunks = 0, []
                    while j < len(rdata):
                        ln = rdata[j]
                        chunks.append(rdata[j + 1:j + 1 + ln].decode("utf-8", "replace"))
                        j += 1 + ln
                    out.append("".join(chunks))
            return out
        except (struct.error, IndexError):
            return []
    return []


def asn_info(ip):
    """ASN, prefijo y pais via Team Cymru (por DNS, sin salida HTTP)."""
    rec = dns_txt("{}.origin.asn.cymru.com".format(reverse(ip)))
    if not rec:
        return None
    f = [x.strip() for x in rec[0].split("|")]
    if len(f) < 3:
        return None
    info = {"asn": f[0], "prefix": f[1], "country": f[2]}
    name = dns_txt("AS{}.asn.cymru.com".format(f[0].split()[0]))
    if name:
        info["as_name"] = name[0].split("|")[-1].strip()
    return info


def extract_ips(text):
    """Saca las IPv4 de un texto libre, sin duplicar y en orden de aparicion."""
    seen, out = set(), []
    for tok in IPV4_RE.findall(text):
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def classify(raw):
    """Devuelve (ip_normalizada, motivo_de_descarte|None)."""
    try:
        ip = ipaddress.IPv4Address(raw)
    except ValueError:
        return None, "no es una IPv4 valida"
    if ip.is_loopback:
        return str(ip), "loopback"
    if ip.is_private:
        return str(ip), "IP privada (RFC1918/CGNAT) — las DNSBL no la listan"
    if ip.is_link_local:
        return str(ip), "link-local"
    if ip.is_multicast:
        return str(ip), "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return str(ip), "reservada"
    return str(ip), None


def reverse(ip):
    return ".".join(reversed(ip.split(".")))


def query(ip, spec, timeout):
    """Consulta una zona. Devuelve dict con codigos y TXT, o None si no listada."""
    host = "{}.{}".format(reverse(ip), spec["zone"])
    socket.setdefaulttimeout(timeout)
    try:
        codes = sorted(socket.gethostbyname_ex(host)[2])
    except socket.gaierror:
        return None          # NXDOMAIN: no listada (o zona sin respuesta)
    except OSError:
        return None
    hits = [c for c in codes if c not in spec.get("ignore", set())]
    if not hits:
        return None
    reason = ""
    for line in dns_txt(host, timeout):
        line = line.strip()
        # Varias listas devuelven solo un enlace de consulta: no es un motivo.
        if line and not line.lower().startswith(("http://", "https://")):
            reason = line
            break
    return {"name": spec["name"], "zone": spec["zone"], "codes": hits,
            "delist": spec["delist"], "note": spec.get("note", ""),
            "reason": reason}


def ptr_of(ip):
    try:
        socket.setdefaulttimeout(5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def check_ip(ip, timeout, workers):
    with futures.ThreadPoolExecutor(workers) as ex:
        results = list(ex.map(lambda s: query(ip, s, timeout), ZONES))
    listings = [r for r in results if r]
    return {"ip": ip, "ptr": ptr_of(ip), "asn": asn_info(ip), "listings": listings,
            "checked": len(ZONES),
            "manual": [{"name": n, "url": u.format(ip=ip)} for n, u in MANUAL]}


def report_text(res, out):
    ip = res["ip"]
    p = out.write
    p("\n" + "=" * 72 + "\n")
    p("IP: {}\n".format(ip))
    ptr = res["ptr"]
    if ptr:
        p("rDNS (PTR): {}\n".format(ptr))
    else:
        p("rDNS (PTR): SIN PTR  <-- causa habitual de rechazo y de listado;\n"
          "            publique un PTR que resuelva de vuelta a la misma IP.\n")
    a = res.get("asn")
    if a:
        p("Origen    : AS{} {} | prefijo {} | {}\n".format(
            a["asn"], a.get("as_name", ""), a["prefix"], a["country"]))
    p("Listas consultadas: {}\n".format(res["checked"]))

    if not res["listings"]:
        p("\nESTADO: LIMPIA en las {} listas consultadas.\n".format(res["checked"]))
    else:
        p("\nESTADO: LISTADA en {} lista(s).\n".format(len(res["listings"])))
        for L in res["listings"]:
            p("\n  * {} ({})\n".format(L["name"], L["zone"]))
            p("    codigo : {}\n".format(", ".join(L["codes"])))
            if L.get("reason"):
                p("    motivo : {}\n".format(L["reason"]))
            p("    desliste: {}\n".format(L["delist"]))
            if L["note"]:
                for n, line in enumerate(_wrap(L["note"], 60)):
                    p("    {} {}\n".format("nota   :" if n == 0 else "        ", line))
    p("\n  Verificar a mano (no responden a resolvers publicos / requieren cuenta):\n")
    for name, url in MANUAL:
        p("    - {:28} {}\n".format(name, url.format(ip=ip)))


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


def scan_block(ip, timeout, workers):
    """Barre el /24 de `ip`. Devuelve {zona: [ips listadas]}."""
    base = ".".join(ip.split(".")[:3])
    jobs = [(n, spec) for n in range(1, 255) for spec in ZONES]

    def one(job):
        n, spec = job
        return spec["zone"], "{}.{}".format(base, n), query("{}.{}".format(base, n),
                                                            spec, timeout)

    found = {}
    with futures.ThreadPoolExecutor(workers) as ex:
        for zone, addr, res in ex.map(one, jobs):
            if res:
                found.setdefault(zone, []).append(addr)
    return {z: sorted(v, key=lambda a: int(a.split(".")[-1]))
            for z, v in found.items()}


def report_block(ip, found, out):
    base = ".".join(ip.split(".")[:3])
    out.write("\n" + "-" * 72 + "\n")
    out.write("Alcance en {}.0/24 (254 IPs)\n\n".format(base))
    if not found:
        out.write("  Ninguna IP del bloque figura en las listas consultadas.\n")
        return
    for zone in sorted(found, key=lambda z: -len(found[z])):
        ips = found[zone]
        veredicto = ("clasificacion del BLOQUE, no de la IP"
                     if len(ips) > 200 else "listado por IP")
        out.write("  {:26} {:3}/254  {}\n".format(zone, len(ips), veredicto))
    out.write("\n  Una lista que marca casi todo el /24 no esta reportando abuso\n"
              "  de una IP: esta clasificando el rango. El desliste individual\n"
              "  no corresponde; lo que corresponde es corregir la clasificacion\n"
              "  del bloque con el dueno del rango.\n")


def main():
    ap = argparse.ArgumentParser(
        description="Valida IPs contra DNSBL y arma el desliste.")
    ap.add_argument("ips", nargs="*", help="IPs a consultar")
    ap.add_argument("--file", "-f", help="archivo de texto del que extraer las IPs")
    ap.add_argument("--json", action="store_true", help="salida JSON")
    ap.add_argument("--timeout", type=float, default=5.0, help="timeout DNS (s)")
    ap.add_argument("--workers", type=int, default=20, help="consultas en paralelo")
    ap.add_argument("--block", action="store_true",
                    help="ademas, barrer el /24 de cada IP para distinguir un "
                         "listado propio de una clasificacion del bloque entero")
    args = ap.parse_args()

    text = " ".join(args.ips)
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            text += " " + fh.read()
    if not sys.stdin.isatty() and not args.ips and not args.file:
        text += " " + sys.stdin.read()

    raw = extract_ips(text)
    if not raw:
        sys.stderr.write("No se encontro ninguna IPv4 en la entrada.\n")
        return 2

    targets, skipped = [], []
    for r in raw:
        ip, why = classify(r)
        (skipped if why else targets).append((ip or r, why))

    results = [check_ip(ip, args.timeout, args.workers) for ip, _ in targets]

    if args.json:
        json.dump({"results": results,
                   "skipped": [{"ip": i, "reason": w} for i, w in skipped]},
                  sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        if skipped:
            sys.stdout.write("Descartadas:\n")
            for i, w in skipped:
                sys.stdout.write("  {:16} {}\n".format(i, w))
        for res in results:
            report_text(res, sys.stdout)
            if args.block:
                report_block(res["ip"],
                             scan_block(res["ip"], args.timeout,
                                        max(args.workers, 60)),
                             sys.stdout)
        listed = [r["ip"] for r in results if r["listings"]]
        sys.stdout.write("\n" + "=" * 72 + "\n")
        sys.stdout.write("RESUMEN: {} IP(s) consultadas, {} listada(s).\n".format(
            len(results), len(listed)))
        if listed:
            sys.stdout.write("Listadas: {}\n".format(", ".join(listed)))
            sys.stdout.write(
                "\nAntes de pedir cualquier desliste: corte el origen del abuso\n"
                "(CPE infectado, cuenta SMTP comprometida, relay abierto), publique\n"
                "PTR y SPF/DKIM/DMARC correctos, y recien ahi envie la solicitud.\n"
                "Un desliste sin arreglar la causa vuelve a listar en horas y\n"
                "endurece el proximo pedido.\n")

    return 1 if any(r["listings"] for r in results) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # La salida se corto (por ejemplo `| head`): no es un error.
        try:
            sys.stdout.close()
        finally:
            sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
