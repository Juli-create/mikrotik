#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chequeos.py -- Bateria de diagnostico de solo lectura para MikroTik RouterOS.

Ningun chequeo modifica el router: solo se ejecutan comandos '/print'.
Cada hallazgo trae severidad, detalle y los comandos sugeridos para corregir
(que TU decides si aplicas; el programa nunca los ejecuta).
"""

import ipaddress
import re

from rosapi import RosError

SEVERIDADES = ["critica", "alta", "media", "baja", "info", "ok"]

# Puertos de administracion que no deberian estar abiertos al mundo.
PUERTOS_ADMIN = {
    "21": "FTP", "22": "SSH", "23": "Telnet", "80": "HTTP (WebFig)",
    "443": "HTTPS (WebFig)", "161": "SNMP", "2000": "bandwidth-test",
    "8291": "WinBox", "8728": "API", "8729": "API-SSL", "5678": "RoMON",
}

# Indicios de scripts/tareas que descargan y ejecutan codigo remoto.
PATRONES_SOSPECHOSOS = [
    (re.compile(r"/tool\s+fetch|:.*\bfetch\b", re.I), "descarga remota (fetch)"),
    (re.compile(r"https?://", re.I), "URL embebida"),
    (re.compile(r"\bbase64\b", re.I), "cadena base64"),
    (re.compile(r":execute\b", re.I), "ejecucion dinamica (:execute)"),
    (re.compile(r"/system\s+script\s+add|/system/script/add", re.I), "se crea otro script"),
    (re.compile(r"/user\s+add|/user/add", re.I), "crea usuarios"),
]


def es_si(v):
    return str(v).strip().lower() in ("true", "yes", "si")


def es_no(v):
    return str(v).strip().lower() in ("false", "no")


def es_publica(ip_txt):
    try:
        red = ipaddress.ip_network(ip_txt.split("%")[0], strict=False)
    except ValueError:
        return False
    return red.is_global


def puertos_de(regla):
    txt = regla.get("dst-port", "")
    out = set()
    for parte in txt.split(","):
        parte = parte.strip()
        if not parte:
            continue
        if "-" in parte:
            try:
                a, b = parte.split("-", 1)
                a, b = int(a), int(b)
                for p in PUERTOS_ADMIN:
                    if a <= int(p) <= b:
                        out.add(p)
            except ValueError:
                pass
        else:
            out.add(parte)
    return out


class Diagnostico:
    def __init__(self, api, incluir_listas=True):
        self.api = api
        self.incluir_listas = incluir_listas
        self.hallazgos = []
        self.datos = {}
        self.errores = {}

    # ------------------------------------------------------------- utilidades

    def leer(self, clave, ruta, *extra):
        """Ejecuta un print y guarda el resultado. Devuelve [] si falla."""
        try:
            filas = self.api.cmd(ruta, *extra)
            self.datos[clave] = filas
            return filas
        except RosError as e:
            self.errores[clave] = str(e)
            return []
        except Exception as e:  # timeouts, rutas inexistentes segun version
            self.errores[clave] = "%s: %s" % (type(e).__name__, e)
            return []

    def add(self, ident, titulo, severidad, estado, detalle, recomendacion=None):
        self.hallazgos.append({
            "id": ident,
            "titulo": titulo,
            "severidad": severidad,
            "estado": estado,
            "detalle": detalle,
            "recomendacion": recomendacion or [],
        })

    # --------------------------------------------------------------- ejecutar

    def ejecutar(self):
        self.recolectar()
        for metodo in (
            self.chk_identidad, self.chk_version, self.chk_recursos,
            self.chk_servicios, self.chk_usuarios, self.chk_ssh,
            self.chk_firewall_input, self.chk_firewall_forward,
            self.chk_nat, self.chk_dns, self.chk_descubrimiento,
            self.chk_servicios_riesgo, self.chk_snmp, self.chk_ntp,
            self.chk_scripts, self.chk_direcciones, self.chk_wireless,
            self.chk_evg,
        ):
            try:
                metodo()
            except Exception as e:
                self.add(metodo.__name__, "Fallo el chequeo " + metodo.__name__,
                         "info", "error", "%s: %s" % (type(e).__name__, e))
        return self.informe()

    def recolectar(self):
        self.leer("identidad", "/system/identity/print")
        self.leer("recursos", "/system/resource/print")
        self.leer("routerboard", "/system/routerboard/print")
        self.leer("servicios", "/ip/service/print")
        self.leer("usuarios", "/user/print")
        self.leer("ssh", "/ip/ssh/print")
        self.leer("filter", "/ip/firewall/filter/print")
        self.leer("nat", "/ip/firewall/nat/print")
        self.leer("dns", "/ip/dns/print")
        self.leer("descubrimiento", "/ip/neighbor/discovery-settings/print")
        self.leer("mac_server", "/tool/mac-server/print")
        self.leer("mac_winbox", "/tool/mac-server/mac-winbox/print")
        self.leer("upnp", "/ip/upnp/print")
        self.leer("socks", "/ip/socks/print")
        self.leer("proxy", "/ip/proxy/print")
        self.leer("smb", "/ip/smb/print")
        self.leer("btest", "/tool/bandwidth-server/print")
        self.leer("romon", "/tool/romon/print")
        self.leer("snmp", "/snmp/print")
        self.leer("snmp_com", "/snmp/community/print")
        self.leer("ntp", "/system/ntp/client/print")
        self.leer("scheduler", "/system/scheduler/print")
        self.leer("scripts", "/system/script/print")
        self.leer("direcciones", "/ip/address/print")
        self.leer("cloud", "/ip/cloud/print")
        self.leer("wireless_sec", "/interface/wireless/security-profiles/print")
        if self.incluir_listas:
            self.leer("address_list", "/ip/firewall/address-list/print",
                      "=.proplist=list,dynamic,disabled")

    # ---------------------------------------------------------------- chequeos

    def chk_identidad(self):
        ident = (self.datos.get("identidad") or [{}])[0].get("name", "?")
        rb = (self.datos.get("routerboard") or [{}])[0]
        modelo = rb.get("model") or (self.datos.get("recursos") or [{}])[0].get("board-name", "?")
        fw_act = rb.get("current-firmware", "")
        fw_dis = rb.get("upgrade-firmware", "")
        detalle = "Identidad: %s\nModelo: %s" % (ident, modelo)
        if fw_act:
            detalle += "\nFirmware RouterBOOT: %s" % fw_act
        if fw_dis and fw_act and fw_dis != fw_act:
            self.add("fw-routerboot", "Firmware de RouterBOOT desactualizado", "baja",
                     "%s -> %s disponible" % (fw_act, fw_dis),
                     detalle + "\nFirmware disponible: %s" % fw_dis,
                     ["/system routerboard upgrade", "/system reboot"])
        else:
            self.add("identidad", "Identificacion del equipo", "info", ident, detalle)

    def chk_version(self):
        rec = (self.datos.get("recursos") or [{}])[0]
        ver = rec.get("version", "?")
        num = re.match(r"(\d+)\.(\d+)", ver)
        mayor = int(num.group(1)) if num else 0
        if mayor and mayor < 7:
            self.add("version", "RouterOS 6.x", "media", ver,
                     "Estas en la rama 6, que ya no recibe funciones nuevas y va "
                     "quedando sin parches. Planifica el salto a la rama 7 "
                     "(revisa compatibilidad de tu hardware y respalda antes).",
                     ["/system package update check-for-updates",
                      "/system backup save name=antes-de-actualizar"])
        else:
            self.add("version", "Version de RouterOS", "info", ver,
                     "Version instalada: %s\nArquitectura: %s\n\nNo puedo saber "
                     "desde aqui cual es la ultima version publicada: comprueba "
                     "actualizaciones en el propio router."
                     % (ver, rec.get("architecture-name", "?")),
                     ["/system package update check-for-updates",
                      "/system package update print"])

    def chk_recursos(self):
        rec = (self.datos.get("recursos") or [{}])[0]
        if not rec:
            return
        try:
            cpu = int(rec.get("cpu-load", "0"))
        except ValueError:
            cpu = 0
        libre = int(rec.get("free-memory", "0") or 0)
        total = int(rec.get("total-memory", "0") or 1)
        pct_libre = 100.0 * libre / total
        detalle = ("CPU: %s%%\nMemoria libre: %.1f MiB de %.1f MiB (%.0f%%)\n"
                   "Uptime: %s" % (cpu, libre / 1048576.0, total / 1048576.0,
                                   pct_libre, rec.get("uptime", "?")))
        if cpu >= 80 or pct_libre < 10:
            self.add("recursos", "Equipo bajo presion", "media",
                     "CPU %s%% / memoria libre %.0f%%" % (cpu, pct_libre), detalle,
                     ["/system resource print", "/tool profile duration=10"])
        else:
            self.add("recursos", "Carga del equipo", "ok",
                     "CPU %s%% / memoria libre %.0f%%" % (cpu, pct_libre), detalle)

    def chk_servicios(self):
        servicios = self.datos.get("servicios") or []
        if not servicios:
            return
        inseguros = {"telnet", "ftp", "www", "api"}
        activos_inseguros, sin_restriccion, apagados = [], [], []
        for s in servicios:
            nombre = s.get("name", "?")
            if es_si(s.get("disabled")):
                apagados.append(nombre)
                continue
            direccion = s.get("address", "").strip()
            if nombre in inseguros:
                activos_inseguros.append("%s (puerto %s)" % (nombre, s.get("port", "?")))
            if not direccion:
                sin_restriccion.append("%s:%s" % (nombre, s.get("port", "?")))

        if activos_inseguros:
            self.add("servicios-inseguros", "Servicios en texto plano habilitados", "alta",
                     ", ".join(activos_inseguros),
                     "telnet, ftp, www y api viajan sin cifrar: usuario y contrasena "
                     "se pueden capturar en la red. Si no los usas, apagalos; si los "
                     "necesitas, usa sus variantes seguras (ssh, winbox, api-ssl).",
                     ["/ip service disable telnet,ftp,www,api"])
        else:
            self.add("servicios-inseguros", "Servicios en texto plano", "ok", "ninguno activo",
                     "telnet/ftp/www/api estan deshabilitados. Bien.")

        if sin_restriccion:
            self.add("servicios-abiertos", "Servicios sin restriccion de origen", "alta",
                     ", ".join(sin_restriccion),
                     "Estos servicios aceptan conexiones desde cualquier direccion "
                     "(campo 'address' vacio). Aunque el firewall los tape, conviene "
                     "cerrarlos tambien aqui: es una segunda capa y sobrevive a un "
                     "error de orden en las reglas.\n\nServicios activos: %s"
                     % ", ".join(sin_restriccion),
                     ["/ip service set ssh address=10.0.0.0/8,TU.IP.FIJA/32",
                      "/ip service set winbox address=10.0.0.0/8,TU.IP.FIJA/32"])
        else:
            self.add("servicios-abiertos", "Restriccion de origen en servicios", "ok",
                     "todos limitados", "Todos los servicios activos tienen 'address' definido.")

    def chk_usuarios(self):
        usuarios = self.datos.get("usuarios") or []
        if not usuarios:
            return
        activos = [u for u in usuarios if not es_si(u.get("disabled"))]
        admin_default = [u for u in activos if u.get("name") == "admin"]
        sin_ip = [u.get("name") for u in activos if not u.get("address", "").strip()]
        full = [u.get("name") for u in activos if u.get("group") == "full"]

        listado = "\n".join(
            "  %-16s grupo=%-8s origen=%s  ultimo acceso=%s"
            % (u.get("name", "?"), u.get("group", "?"),
               u.get("address", "cualquiera"), u.get("last-logged-in", "-"))
            for u in activos)

        if admin_default:
            self.add("usuario-admin", "Usuario 'admin' por defecto activo", "media",
                     "presente",
                     "El usuario 'admin' es el primero que prueba cualquier ataque de "
                     "fuerza bruta. Crea un usuario propio con grupo full, verifica "
                     "que entras con el, y recien entonces deshabilita 'admin'.\n\n"
                     "Usuarios activos:\n" + listado,
                     ["/user add name=TU_USUARIO group=full password=UNA_CLAVE_LARGA",
                      "# entra con el usuario nuevo y comprueba que funciona",
                      "/user disable admin"])

        if sin_ip:
            self.add("usuarios-sin-origen", "Usuarios sin restriccion de origen", "media",
                     ", ".join(sin_ip),
                     "Estos usuarios pueden autenticarse desde cualquier IP. Limitarlos "
                     "a tu red de gestion reduce mucho la superficie de ataque.\n\n"
                     "Usuarios activos:\n" + listado,
                     ["/user set TU_USUARIO address=10.0.0.0/8,TU.IP.FIJA/32"])

        if len(full) > 2:
            self.add("usuarios-full", "Varios usuarios con permisos totales", "baja",
                     "%d usuarios en grupo full" % len(full),
                     "Con grupo 'full' cualquiera de ellos puede reconfigurar el equipo "
                     "entero. Considera grupos con permisos acotados (solo lectura para "
                     "monitoreo, por ejemplo).\n\nUsuarios full: " + ", ".join(full),
                     ["/user group add name=solo-lectura policy=read,winbox,api,test",
                      "/user set NOMBRE group=solo-lectura"])

        if not admin_default and not sin_ip:
            self.add("usuarios", "Cuentas de administracion", "ok",
                     "%d usuarios activos" % len(activos), "Usuarios activos:\n" + listado)

    def chk_ssh(self):
        ssh = (self.datos.get("ssh") or [{}])[0]
        if not ssh:
            return
        fuerte = es_si(ssh.get("strong-crypto"))
        con_clave = es_no(ssh.get("always-allow-password-login"))
        detalle = ("strong-crypto: %s\nalways-allow-password-login: %s\n"
                   "forwarding: %s" % (ssh.get("strong-crypto", "?"),
                                       ssh.get("always-allow-password-login", "?"),
                                       ssh.get("forwarding-enabled", "?")))
        if not fuerte:
            self.add("ssh-crypto", "SSH sin strong-crypto", "media", "desactivado",
                     detalle + "\n\nCon strong-crypto=no el router acepta algoritmos "
                     "antiguos y claves de host cortas.",
                     ["/ip ssh set strong-crypto=yes",
                      "/ip ssh regenerate-host-key"])
        elif not con_clave:
            self.add("ssh-clave", "SSH acepta contrasena", "baja", "password permitido",
                     detalle + "\n\nCon clave publica importada puedes exigir solo clave "
                     "y cerrar la puerta a la fuerza bruta.",
                     ["/user ssh-keys import public-key-file=id_ed25519.pub user=TU_USUARIO",
                      "/ip ssh set always-allow-password-login=no"])
        else:
            self.add("ssh", "Configuracion de SSH", "ok", "endurecido", detalle)

    def _reglas(self, cadena):
        return [r for r in (self.datos.get("filter") or [])
                if r.get("chain") == cadena and not es_si(r.get("disabled"))]

    def chk_firewall_input(self):
        todas = self.datos.get("filter") or []
        if not todas:
            self.add("firewall-vacio", "No se pudo leer el firewall", "info", "sin datos",
                     "No hay reglas legibles en /ip/firewall/filter. Si el usuario tiene "
                     "permisos limitados, este diagnostico queda incompleto.")
            return

        reglas = self._reglas("input")
        idx_drop = None
        for i, r in enumerate(reglas):
            if (r.get("action") in ("drop", "reject")
                    and not r.get("dst-port") and not r.get("protocol")
                    and not r.get("src-address") and not r.get("src-address-list")):
                idx_drop = i
                break

        if idx_drop is None:
            self.add("input-sin-drop", "La cadena input no termina en drop", "critica",
                     "sin regla de cierre",
                     "No encontre una regla final que descarte todo lo que no fue "
                     "aceptado explicitamente. Sin ella, cualquier puerto que abras (o "
                     "que abra un servicio nuevo) queda accesible.\n\n"
                     "Aplica el cierre SIEMPRE en safe-mode (F4 en la terminal de "
                     "WinBox): si te dejas fuera, RouterOS revierte solo.",
                     ["# primero acepta lo que necesitas (establecidas, tu red de gestion)",
                      "/ip firewall filter add chain=input connection-state=established,related action=accept",
                      "/ip firewall filter add chain=input src-address-list=ADMIN-OK action=accept",
                      "# y solo despues cierra",
                      "/ip firewall filter add chain=input action=drop comment=\"cierre input\""])
        else:
            despues = len(reglas) - idx_drop - 1
            estado = "regla %d de %d" % (idx_drop + 1, len(reglas))
            if despues:
                self.add("input-inalcanzables", "Reglas inalcanzables tras el drop de input",
                         "media", "%d regla(s) despues del cierre" % despues,
                         "Hay %d reglas activas colocadas DESPUES de la regla que "
                         "descarta todo, asi que nunca se evaluan. Suelen ser accesos "
                         "que crees tener y no tienes. Muevelas antes del cierre."
                         % despues,
                         ["/ip firewall filter print",
                          "/ip firewall filter move NUMERO destination=%d" % idx_drop])
            else:
                self.add("input-drop", "Cierre de la cadena input", "ok", estado,
                         "La cadena input termina descartando lo no aceptado.")

        expuestos = []
        for r in reglas[:idx_drop if idx_drop is not None else len(reglas)]:
            if r.get("action") != "accept":
                continue
            if r.get("src-address") or r.get("src-address-list"):
                continue
            for p in puertos_de(r):
                if p in PUERTOS_ADMIN:
                    expuestos.append("%s/%s" % (PUERTOS_ADMIN[p], p))
        if expuestos:
            self.add("input-admin-abierto", "Puertos de administracion aceptados desde cualquier origen",
                     "critica", ", ".join(sorted(set(expuestos))),
                     "Hay reglas que aceptan estos puertos sin limitar el origen. En una "
                     "IP publica esto recibe intentos de acceso constantes.\n\n"
                     "Lo correcto es una lista de direcciones de gestion, o mejor, no "
                     "exponer administracion y entrar por VPN (WireGuard).",
                     ["/ip firewall address-list add list=ADMIN-OK address=TU.IP.FIJA comment=\"gestion\"",
                      "# y en la regla de accept, exigir esa lista:",
                      "/ip firewall filter set NUMERO src-address-list=ADMIN-OK"])

        deshabilitadas = [r for r in todas if es_si(r.get("disabled"))]
        if deshabilitadas:
            self.add("firewall-deshabilitadas", "Reglas de firewall deshabilitadas", "info",
                     "%d de %d" % (len(deshabilitadas), len(todas)),
                     "Hay %d reglas apagadas. Puede ser intencional (tu script deja "
                     "algunos drops en observacion), pero conviene revisar que no sea "
                     "una proteccion que quedo desactivada por una prueba."
                     % len(deshabilitadas),
                     ["/ip firewall filter print where disabled=yes"])

    def chk_firewall_forward(self):
        reglas = self._reglas("forward")
        if not reglas:
            return
        cierre = any(r.get("action") in ("drop", "reject") and not r.get("dst-port")
                     for r in reglas)
        if not cierre:
            self.add("forward-sin-drop", "La cadena forward no tiene regla de cierre", "media",
                     "sin drop final",
                     "El trafico que atraviesa el router pasa por defecto. En un router "
                     "de borde de ISP esto puede ser lo buscado; en un router de red "
                     "interna normalmente no. Revisa si es intencional.",
                     ["/ip firewall filter print where chain=forward"])
        else:
            self.add("forward", "Cadena forward", "ok", "%d reglas activas" % len(reglas),
                     "La cadena forward tiene regla de cierre.")

    def chk_nat(self):
        nat = self.datos.get("nat") or []
        dst = [r for r in nat if r.get("chain") == "dstnat" and not es_si(r.get("disabled"))]
        if not dst:
            return
        loopback, listado = [], []
        for r in dst:
            destino = r.get("to-addresses", "") or r.get("to-address", "")
            listado.append("  %s:%s -> %s:%s  %s"
                           % (r.get("dst-address", "cualquiera"), r.get("dst-port", "-"),
                              destino or "-", r.get("to-ports", "-"),
                              r.get("comment", "")))
            if destino.startswith("127."):
                loopback.append(r.get("dst-port", "?"))
        if loopback:
            self.add("nat-loopback", "Redireccion NAT hacia 127.0.0.1", "critica",
                     "puertos " + ", ".join(loopback),
                     "Una regla dst-nat que apunta a 127.0.0.1 es una tecnica conocida "
                     "para exponer servicios internos del router saltandose el firewall. "
                     "Si no la pusiste tu, tratala como indicio de compromiso: revisa "
                     "usuarios, scripts y programador, y considera reinstalar.\n\n"
                     "Reglas dstnat:\n" + "\n".join(listado),
                     ["/ip firewall nat print where action=dst-nat",
                      "/ip firewall nat remove NUMERO"])
        else:
            self.add("nat-dstnat", "Redirecciones de puertos (dst-nat)", "info",
                     "%d activas" % len(dst),
                     "Cada una de estas expone un servicio interno hacia fuera. "
                     "Comprueba que todas siguen siendo necesarias:\n" + "\n".join(listado))

    def chk_dns(self):
        dns = (self.datos.get("dns") or [{}])[0]
        if not dns:
            return
        remoto = es_si(dns.get("allow-remote-requests"))
        detalle = ("allow-remote-requests: %s\nservidores: %s\ncache: %s KiB"
                   % (dns.get("allow-remote-requests", "?"), dns.get("servers", "-"),
                      dns.get("cache-size", "?")))
        if not remoto:
            self.add("dns", "Resolver DNS del router", "ok", "no atiende consultas externas",
                     detalle)
            return

        protegido = False
        for r in self._reglas("input"):
            if r.get("action") in ("drop", "reject") and "53" in puertos_de(r):
                protegido = True
        sev = "media" if protegido else "alta"
        self.add("dns-abierto", "El router resuelve DNS para terceros", sev,
                 "allow-remote-requests=yes",
                 detalle + "\n\nCon esto activo el router responde consultas DNS. Si el "
                 "puerto 53 queda alcanzable desde internet te conviertes en resolver "
                 "abierto: te usan para amplificar ataques y acabas en listas negras.\n\n"
                 "Es normal tenerlo activo para los clientes internos; lo importante es "
                 "que el 53 este cerrado en la interfaz WAN.",
                 ["/ip firewall filter add chain=input protocol=udp dst-port=53 in-interface-list=WAN action=drop",
                  "/ip firewall filter add chain=input protocol=tcp dst-port=53 in-interface-list=WAN action=drop"])

    def chk_descubrimiento(self):
        desc = (self.datos.get("descubrimiento") or [{}])[0]
        lista = desc.get("discover-interface-list", "")
        if lista and lista not in ("none", "!WAN"):
            self.add("neighbor", "Descubrimiento de vecinos amplio", "media", lista,
                     "El protocolo de descubrimiento (MNDP/CDP/LLDP) anuncia modelo, "
                     "version e identidad del equipo en '%s'. Limitalo a las interfaces "
                     "internas de gestion." % lista,
                     ["/interface list add name=DESCUBRIR",
                      "/interface list member add list=DESCUBRIR interface=TU_LAN_DE_GESTION",
                      "/ip neighbor discovery-settings set discover-interface-list=DESCUBRIR"])

        for clave, etiqueta, cmd in (
            ("mac_server", "MAC-Telnet", "/tool mac-server set allowed-interface-list=none"),
            ("mac_winbox", "MAC-WinBox", "/tool mac-server mac-winbox set allowed-interface-list=none"),
        ):
            fila = (self.datos.get(clave) or [{}])[0]
            permitido = fila.get("allowed-interface-list", "")
            if permitido and permitido not in ("none",):
                sev = "alta" if permitido == "all" else "media"
                self.add(clave, "%s habilitado en '%s'" % (etiqueta, permitido), sev,
                         permitido,
                         "%s permite administrar el equipo por direccion MAC, sin pasar "
                         "por IP ni por el firewall. Util para rescate en la LAN, "
                         "peligroso si alcanza a interfaces de clientes o WAN.\n\n"
                         "Si lo dejas, limitalo a una lista de interfaces de gestion."
                         % etiqueta,
                         [cmd])

    def chk_servicios_riesgo(self):
        pares = [
            ("socks", "/ip/socks", "critica",
             "El proxy SOCKS es una de las senales clasicas de un MikroTik comprometido: "
             "los botnets lo activan para reenviar trafico ajeno a traves de tu equipo. "
             "Si no lo configuraste tu, revisa usuarios, scripts y programador.",
             ["/ip socks set enabled=no", "/ip socks access remove [find]"]),
            ("proxy", "/ip/proxy", "alta",
             "El proxy web de RouterOS, si queda abierto, lo usan terceros para navegar "
             "a traves de tu conexion. Apagalo si no lo usas.",
             ["/ip proxy set enabled=no"]),
            ("upnp", "/ip/upnp", "alta",
             "UPnP permite que cualquier equipo de la red abra puertos hacia internet "
             "por su cuenta, sin que quede registro claro. Desactivado por defecto por "
             "algo.",
             ["/ip upnp set enabled=no"]),
            ("smb", "/ip/smb", "media",
             "El servidor SMB del router expone comparticion de archivos. Ha tenido "
             "vulnerabilidades y rara vez hace falta.",
             ["/ip smb set enabled=no"]),
            ("romon", "/tool/romon", "media",
             "RoMON permite administrar el equipo desde otro MikroTik de la misma capa 2. "
             "Si esta activo sin contrasena ni restriccion de puertos, es un camino de "
             "entrada lateral.",
             ["/tool romon set enabled=no"]),
        ]
        for clave, ruta, sev, texto, cmds in pares:
            fila = (self.datos.get(clave) or [{}])[0]
            if not fila:
                continue
            if es_si(fila.get("enabled")):
                extra = "\n\nEstado leido: " + ", ".join(
                    "%s=%s" % (k, v) for k, v in sorted(fila.items()) if not k.startswith("."))
                self.add(clave, "%s habilitado" % ruta, sev, "enabled=yes", texto + extra, cmds)

        btest = (self.datos.get("btest") or [{}])[0]
        if btest and es_si(btest.get("enabled")) and not es_si(btest.get("authenticate")):
            self.add("btest", "Servidor bandwidth-test sin autenticacion", "alta",
                     "abierto",
                     "Cualquiera puede lanzar una prueba de ancho de banda contra el "
                     "router y saturar tanto el enlace como la CPU. Es un vector de "
                     "denegacion de servicio gratuito.",
                     ["/tool bandwidth-server set enabled=no",
                      "# o al menos: /tool bandwidth-server set authenticate=yes"])

    def chk_snmp(self):
        snmp = (self.datos.get("snmp") or [{}])[0]
        if not snmp or not es_si(snmp.get("enabled")):
            return
        comunidades = [c.get("name", "?") for c in (self.datos.get("snmp_com") or [])]
        debiles = [c for c in comunidades if c.lower() in ("public", "private")]
        sev = "alta" if debiles else "media"
        self.add("snmp", "SNMP habilitado", sev,
                 "comunidades: " + (", ".join(comunidades) or "?"),
                 "SNMP entrega inventario completo del equipo a quien pregunte. "
                 + ("Ademas usas la comunidad por defecto (%s), que es lo primero que "
                    "prueba cualquier escaneo.\n\n" % ", ".join(debiles) if debiles else "\n")
                 + "Si lo necesitas para monitoreo, usa SNMPv3 con autenticacion y "
                   "limita el acceso por firewall a tu servidor de monitoreo.",
                 ["/snmp community set [find name=public] name=UNA_CADENA_LARGA addresses=IP.DEL.MONITOREO/32",
                  "/ip firewall filter add chain=input protocol=udp dst-port=161 src-address=IP.DEL.MONITOREO action=accept",
                  "/ip firewall filter add chain=input protocol=udp dst-port=161 action=drop"])

    def chk_ntp(self):
        ntp = (self.datos.get("ntp") or [{}])[0]
        if not ntp:
            return
        if not es_si(ntp.get("enabled")):
            self.add("ntp", "Cliente NTP desactivado", "baja", "sin sincronizacion",
                     "Sin hora correcta los registros no sirven para investigar un "
                     "incidente y los certificados fallan.",
                     ["/system ntp client set enabled=yes servers=pool.ntp.org"])
        else:
            self.add("ntp", "Sincronizacion de hora", "ok", ntp.get("servers", "activo"),
                     "Cliente NTP activo. Servidores: %s" % ntp.get("servers", "?"))

    def chk_scripts(self):
        scripts = self.datos.get("scripts") or []
        tareas = self.datos.get("scheduler") or []
        sospechosos = []

        def revisar(nombre, cuerpo, origen):
            if nombre.upper().startswith("EVG"):
                return  # tus propios scripts del firewall EVG
            motivos = [etiqueta for patron, etiqueta in PATRONES_SOSPECHOSOS
                       if patron.search(cuerpo or "")]
            if motivos:
                sospechosos.append("  [%s] %s -> %s" % (origen, nombre, ", ".join(motivos)))

        for s in scripts:
            revisar(s.get("name", "?"), s.get("source", "")[:4000], "script")
        for t in tareas:
            revisar(t.get("name", "?"), t.get("on-event", "")[:4000], "tarea")

        if sospechosos:
            self.add("scripts-sospechosos", "Scripts o tareas con patrones a revisar", "alta",
                     "%d coincidencia(s)" % len(sospechosos),
                     "Encontre scripts o tareas programadas que descargan contenido, "
                     "ejecutan codigo dinamico o crean usuarios. Puede ser legitimo (un "
                     "script tuyo de respaldo o de listas negras), pero es exactamente lo "
                     "que deja un compromiso para persistir. Revisa cada uno y borra lo "
                     "que no reconozcas:\n\n" + "\n".join(sospechosos)
                     + "\n\n(Los scripts cuyo nombre empieza por EVG se omiten: son los "
                       "tuyos del firewall.)",
                     ["/system script print detail",
                      "/system scheduler print detail",
                      "/system scheduler remove [find name=NOMBRE]"])
        else:
            self.add("scripts", "Scripts y tareas programadas", "ok",
                     "%d script(s), %d tarea(s)" % (len(scripts), len(tareas)),
                     "Sin patrones sospechosos (descargas remotas, base64, :execute).")

    def chk_direcciones(self):
        direcciones = self.datos.get("direcciones") or []
        publicas, listado = [], []
        for d in direcciones:
            addr = d.get("address", "")
            iface = d.get("interface", "?")
            listado.append("  %-22s %s" % (addr, iface))
            if es_publica(addr):
                publicas.append("%s en %s" % (addr, iface))
        if listado:
            self.add("direcciones", "Direcciones IP configuradas",
                     "info" if not publicas else "info",
                     "%d direccion(es), %d publica(s)" % (len(direcciones), len(publicas)),
                     "\n".join(listado)
                     + ("\n\nDirecciones publicas (alcanzables desde internet):\n  "
                        + "\n  ".join(publicas) if publicas else ""))
        cloud = (self.datos.get("cloud") or [{}])[0]
        if cloud and es_si(cloud.get("ddns-enabled")):
            self.add("cloud", "IP Cloud / DDNS activo", "info",
                     cloud.get("dns-name", "activo"),
                     "El router publica su IP en el DNS dinamico de MikroTik: %s\n"
                     "Comodo para administrar, pero tambien hace tu equipo facil de "
                     "encontrar. Tenlo presente."
                     % cloud.get("dns-name", "?"))

    def chk_wireless(self):
        perfiles = self.datos.get("wireless_sec") or []
        abiertos = [p.get("name", "?") for p in perfiles
                    if p.get("mode", "none") == "none"]
        if abiertos and len(perfiles) > 1:
            self.add("wifi-abierto", "Perfiles wireless sin cifrado", "alta",
                     ", ".join(abiertos),
                     "Estos perfiles de seguridad no cifran (mode=none). Si estan en uso "
                     "en alguna interfaz, esa red es abierta.\n\n"
                     "El perfil 'default' suele venir asi de fabrica y no pasa nada si "
                     "ninguna interfaz lo usa: comprueba con el comando de abajo.",
                     ["/interface wireless print where security-profile=default"])

    def chk_evg(self):
        """Integracion con el firewall EVG-FW2026 de este repositorio."""
        entradas = self.datos.get("address_list")
        if entradas is None:
            return
        conteo = {}
        for e in entradas:
            nombre = e.get("list", "?")
            conteo[nombre] = conteo.get(nombre, 0) + 1

        evg = {k: v for k, v in conteo.items()
               if k.startswith(("CPE-", "EVG-", "DNS-OK", "PORT-SCAN", "CENSO-"))}
        if not evg:
            self.add("evg", "Firewall EVG-FW2026", "info", "no detectado",
                     "No encontre listas del script EVG-FW2026 (CPE-*, EVG-*, PORT-SCAN). "
                     "Si esperabas tenerlo cargado, revisa que la importacion "
                     "haya terminado sin errores.",
                     ["/import file-name=EVG-FW2026-v7.14.rsc verbose=yes"])
            return

        resumen = "\n".join("  %-24s %d" % (k, v) for k, v in sorted(evg.items()))
        infectados = evg.get("CPE-INFECTADO", 0)
        if infectados:
            self.add("evg-infectados", "Equipos marcados como infectados", "alta",
                     "%d en CPE-INFECTADO" % infectados,
                     "El firewall EVG tiene %d equipos en CPE-INFECTADO (senal dura: "
                     "sinkhole, honeypot o propagacion IoT). Estos son los que conviene "
                     "atender primero.\n\nListas EVG encontradas:\n%s"
                     % (infectados, resumen),
                     ["/ip firewall address-list print where list=CPE-INFECTADO"])
        else:
            self.add("evg", "Firewall EVG-FW2026", "ok",
                     "%d listas activas" % len(evg),
                     "Listas EVG encontradas:\n" + resumen)

        tareas = [t.get("name", "") for t in (self.datos.get("scheduler") or [])]
        calibra = [t for t in tareas if "CALIBRA" in t.upper()]
        if not calibra:
            self.add("evg-calibra", "EVG-CALIBRA no esta programado", "media",
                     "sin tarea",
                     "No hay una tarea programada de EVG-CALIBRA. Sin ella los umbrales "
                     "no se autoajustan y las listas de aprendizaje (DNS-OK por consenso, "
                     "EVG-NO-AUTOBLOCK) no se refrescan.",
                     ["/system scheduler print"])

    # ---------------------------------------------------------------- informe

    def informe(self):
        resumen = {s: 0 for s in SEVERIDADES}
        for h in self.hallazgos:
            resumen[h["severidad"]] = resumen.get(h["severidad"], 0) + 1
        orden = {s: i for i, s in enumerate(SEVERIDADES)}
        self.hallazgos.sort(key=lambda h: (orden.get(h["severidad"], 9), h["titulo"]))

        rec = (self.datos.get("recursos") or [{}])[0]
        ident = (self.datos.get("identidad") or [{}])[0]
        return {
            "equipo": {
                "identidad": ident.get("name", "?"),
                "modelo": rec.get("board-name", "?"),
                "version": rec.get("version", "?"),
                "uptime": rec.get("uptime", "?"),
            },
            "resumen": resumen,
            "hallazgos": self.hallazgos,
            "errores": self.errores,
        }
