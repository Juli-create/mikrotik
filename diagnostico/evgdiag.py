#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EVG-DIAG -- Diagnostico de MikroTik RouterOS con interfaz web local.

  python3 evgdiag.py            abre el navegador con el formulario
  python3 evgdiag.py --cli ...  ejecuta el diagnostico sin navegador

Todo corre en tu maquina: el servidor escucha solo en 127.0.0.1 y las
credenciales viven en memoria durante la consulta. No se guardan en disco ni
se envian a ningun servicio externo.

Requiere unicamente Python 3.8+ (sin pip install).
"""

import argparse
import json
import os
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from chequeos import Diagnostico, SEVERIDADES  # noqa: E402
from rosapi import RosApi, RosError  # noqa: E402

AQUI = os.path.dirname(os.path.abspath(__file__))
TOKEN = secrets.token_urlsafe(24)


def diagnosticar(host, puerto, usuario, password, tls, timeout, incluir_listas=True):
    """Conecta, ejecuta la bateria y devuelve el informe como dict."""
    api = RosApi(host, puerto, tls, timeout)
    api.connect()
    try:
        api.login(usuario, password)
        return Diagnostico(api, incluir_listas).ejecutar()
    finally:
        api.close()


# --------------------------------------------------------------------- web

class Handler(BaseHTTPRequestHandler):
    server_version = "EVG-DIAG"

    def log_message(self, fmt, *args):  # menos ruido en la consola
        if "--verbose" in sys.argv:
            super().log_message(fmt, *args)

    # Un sitio web malicioso podria intentar hablar con este servidor local.
    # Por eso: token obligatorio y Host restringido a localhost.
    def _host_local(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]", "::1")

    def _json(self, obj, code=200):
        cuerpo = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_GET(self):
        if not self._host_local():
            self.send_error(403, "Solo accesible desde localhost")
            return
        ruta, _, consulta = self.path.partition("?")
        if ruta in ("/", "/index.html"):
            params = dict(p.split("=", 1) for p in consulta.split("&") if "=" in p)
            if not secrets.compare_digest(params.get("t", ""), TOKEN):
                self.send_error(403, "Falta el token. Abre el enlace que imprimio el programa.")
                return
            try:
                with open(os.path.join(AQUI, "ui.html"), "rb") as fh:
                    cuerpo = fh.read()
            except OSError:
                self.send_error(500, "No encuentro ui.html junto a evgdiag.py")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(cuerpo)
            return
        if ruta == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        self.send_error(404)

    def do_POST(self):
        if not self._host_local():
            self.send_error(403, "Solo accesible desde localhost")
            return
        if self.path != "/api/diagnostico":
            self.send_error(404)
            return
        if not secrets.compare_digest(self.headers.get("X-EVG-Token", ""), TOKEN):
            self._json({"error": "Token invalido. Recarga la pagina desde el enlace original."}, 403)
            return

        try:
            largo = int(self.headers.get("Content-Length", "0"))
            datos = json.loads(self.rfile.read(largo) or b"{}")
        except (ValueError, OSError):
            self._json({"error": "Peticion mal formada."}, 400)
            return

        host = (datos.get("host") or "").strip()
        usuario = (datos.get("usuario") or "").strip()
        password = datos.get("password") or ""
        tls = bool(datos.get("tls"))
        listas = datos.get("listas", True)
        try:
            puerto = int(datos.get("puerto") or (8729 if tls else 8728))
            timeout = float(datos.get("timeout") or 10)
        except ValueError:
            self._json({"error": "Puerto o tiempo de espera invalidos."}, 400)
            return

        if not host or not usuario:
            self._json({"error": "Faltan la direccion del router o el usuario."}, 400)
            return

        try:
            informe = diagnosticar(host, puerto, usuario, password, tls, timeout, listas)
        except RosError as e:
            self._json({"error": "El router rechazo la sesion: %s" % e}, 502)
            return
        except OSError as e:
            self._json({"error": "No se pudo conectar con %s:%s -- %s\n\nComprueba que el "
                                 "servicio api este habilitado (/ip service enable api) y "
                                 "que el firewall permita tu IP."
                                 % (host, puerto, e)}, 502)
            return
        except Exception as e:
            self._json({"error": "%s: %s" % (type(e).__name__, e)}, 500)
            return

        informe["conexion"] = {"host": host, "puerto": puerto, "tls": tls, "usuario": usuario}
        self._json(informe)


def servir(puerto_web, abrir):
    servidor = ThreadingHTTPServer(("127.0.0.1", puerto_web), Handler)
    url = "http://127.0.0.1:%d/?t=%s" % (servidor.server_port, TOKEN)
    print("\n  EVG-DIAG escuchando solo en tu maquina.")
    print("  Abre esta direccion en el navegador:\n")
    print("      " + url + "\n")
    print("  (Ctrl+C para detener)\n")
    if abrir:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n  Detenido.\n")
    finally:
        servidor.server_close()


# --------------------------------------------------------------------- cli

def imprimir_informe(informe):
    eq = informe["equipo"]
    print("\n  %s  --  %s  --  RouterOS %s  --  uptime %s\n"
          % (eq["identidad"], eq["modelo"], eq["version"], eq["uptime"]))
    res = informe["resumen"]
    print("  " + "   ".join("%s: %d" % (s, res.get(s, 0)) for s in SEVERIDADES if res.get(s)))
    print()
    for h in informe["hallazgos"]:
        print("  [%-7s] %s  --  %s" % (h["severidad"].upper(), h["titulo"], h["estado"]))
    print()
    for h in informe["hallazgos"]:
        if h["severidad"] in ("ok", "info"):
            continue
        print("-" * 78)
        print("[%s] %s  (%s)" % (h["severidad"].upper(), h["titulo"], h["estado"]))
        print(h["detalle"])
        if h["recomendacion"]:
            print("\n  Sugerido:")
            for c in h["recomendacion"]:
                print("    " + c)
        print()


def main():
    p = argparse.ArgumentParser(description="Diagnostico de MikroTik RouterOS")
    p.add_argument("--puerto-web", type=int, default=8777, help="puerto local de la interfaz")
    p.add_argument("--no-abrir", action="store_true", help="no abrir el navegador solo")
    p.add_argument("--cli", action="store_true", help="ejecutar sin interfaz web")
    p.add_argument("--host", help="IP o nombre del router (modo --cli)")
    p.add_argument("--usuario", help="usuario de RouterOS (modo --cli)")
    p.add_argument("--password", help="contrasena; si se omite se pide por teclado")
    p.add_argument("--puerto", type=int, help="puerto de la API (8728, u 8729 con --tls)")
    p.add_argument("--tls", action="store_true", help="usar api-ssl")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", metavar="ARCHIVO", help="guardar el informe en JSON")
    args = p.parse_args()

    if not args.cli:
        servir(args.puerto_web, not args.no_abrir)
        return 0

    if not args.host or not args.usuario:
        p.error("--cli necesita --host y --usuario")
    password = args.password
    if password is None:
        import getpass
        password = getpass.getpass("Contrasena de %s: " % args.usuario)
    puerto = args.puerto or (8729 if args.tls else 8728)
    try:
        informe = diagnosticar(args.host, puerto, args.usuario, password,
                               args.tls, args.timeout)
    except (RosError, OSError) as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1
    imprimir_informe(informe)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(informe, fh, ensure_ascii=False, indent=2)
        print("  Informe guardado en %s\n" % args.json)
    graves = sum(informe["resumen"].get(s, 0) for s in ("critica", "alta"))
    return 2 if graves else 0


if __name__ == "__main__":
    sys.exit(main())
