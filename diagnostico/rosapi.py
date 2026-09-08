#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rosapi.py -- Cliente minimo de la API nativa de MikroTik RouterOS.

Sin dependencias externas: solo socket, ssl, hashlib y struct.

Protocolo (documentado por MikroTik):
  - Una "frase" (sentence) es una lista de "palabras" (words) terminada en
    una palabra vacia.
  - Cada palabra va precedida de su longitud codificada en 1..5 bytes.
  - La respuesta llega como frases cuyo primer word es !re, !done, !trap o
    !fatal.

Login:
  - RouterOS >= 6.43: se envia usuario y contrasena en claro dentro de la
    sesion (por eso conviene usar api-ssl / puerto 8729).
  - RouterOS <  6.43: reto MD5. Se implementan los dos.
"""

import binascii
import hashlib
import socket
import ssl
import struct


class RosError(Exception):
    """Error devuelto por el router (!trap / !fatal) o de protocolo."""


class RosApi:
    def __init__(self, host, port=8728, use_tls=False, timeout=10.0):
        self.host = host
        self.port = int(port)
        self.use_tls = bool(use_tls)
        self.timeout = float(timeout)
        self.sock = None

    # ---------------------------------------------------------------- socket

    def connect(self):
        raw = socket.create_connection((self.host, self.port), self.timeout)
        raw.settimeout(self.timeout)
        if not self.use_tls:
            self.sock = raw
            return

        # RouterOS con api-ssl y sin certificado propio negocia Anonymous DH,
        # que OpenSSL moderno rechaza por defecto. Se intenta lo normal y se
        # cae a ADH si hace falta.
        for ciphers in (None, "ADH:@SECLEVEL=0", "ALL:@SECLEVEL=0"):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if ciphers:
                    ctx.set_ciphers(ciphers)
                self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
                return
            except (ssl.SSLError, OSError):
                try:
                    raw.close()
                except OSError:
                    pass
                raw = socket.create_connection((self.host, self.port), self.timeout)
                raw.settimeout(self.timeout)
        raise RosError(
            "No se pudo negociar TLS con el puerto api-ssl. Prueba sin TLS "
            "(puerto 8728) o instala un certificado en el router."
        )

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ------------------------------------------------------------ bajo nivel

    def _send_all(self, data):
        self.sock.sendall(data)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise RosError("El router cerro la conexion inesperadamente.")
            buf += chunk
        return buf

    @staticmethod
    def _encode_len(n):
        if n < 0x80:
            return bytes([n])
        if n < 0x4000:
            return struct.pack(">H", n | 0x8000)
        if n < 0x200000:
            return struct.pack(">I", n | 0xC00000)[1:]
        if n < 0x10000000:
            return struct.pack(">I", n | 0xE0000000)
        return b"\xf0" + struct.pack(">I", n)

    def _decode_len(self):
        c = self._recv_exact(1)[0]
        if c & 0x80 == 0x00:
            return c
        if c & 0xC0 == 0x80:
            return ((c & ~0xC0) << 8) + self._recv_exact(1)[0]
        if c & 0xE0 == 0xC0:
            b = self._recv_exact(2)
            return ((c & ~0xE0) << 16) + (b[0] << 8) + b[1]
        if c & 0xF0 == 0xE0:
            b = self._recv_exact(3)
            return ((c & ~0xF0) << 24) + (b[0] << 16) + (b[1] << 8) + b[2]
        if c & 0xF8 == 0xF0:
            return struct.unpack(">I", self._recv_exact(4))[0]
        raise RosError("Longitud de palabra invalida en la respuesta.")

    def _send_sentence(self, words):
        out = b""
        for w in words:
            wb = w.encode("utf-8", "replace")
            out += self._encode_len(len(wb)) + wb
        out += b"\x00"
        self._send_all(out)

    def _read_word(self):
        n = self._decode_len()
        if n == 0:
            return ""
        return self._recv_exact(n).decode("utf-8", "replace")

    def _read_sentence(self):
        words = []
        while True:
            w = self._read_word()
            if w == "":
                return words
            words.append(w)

    # ----------------------------------------------------------- alto nivel

    @staticmethod
    def _parse_attrs(words):
        attrs = {}
        for w in words:
            if w.startswith("=") and "=" in w[1:]:
                k, _, v = w[1:].partition("=")
                attrs[k] = v
            elif w.startswith("="):
                attrs[w[1:]] = ""
        return attrs

    def talk(self, words):
        """Envia una frase y devuelve (lista_de_!re, atributos_del_!done)."""
        self._send_sentence(words)
        filas, done = [], {}
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            tipo, resto = sentence[0], sentence[1:]
            if tipo == "!re":
                filas.append(self._parse_attrs(resto))
            elif tipo == "!done":
                done = self._parse_attrs(resto)
                return filas, done
            elif tipo == "!trap":
                a = self._parse_attrs(resto)
                raise RosError(a.get("message", "error desconocido del router"))
            elif tipo == "!fatal":
                raise RosError("Conexion terminada por el router: " + " ".join(resto))

    def login(self, usuario, password):
        filas, done = self.talk(["/login", "=name=" + usuario, "=password=" + password])
        reto = done.get("ret")
        if not reto:
            return  # RouterOS moderno: ya quedo autenticado
        # RouterOS antiguo (< 6.43): reto MD5
        desafio = binascii.unhexlify(reto)
        md5 = hashlib.md5(b"\x00" + password.encode("utf-8") + desafio).hexdigest()
        self.talk(["/login", "=name=" + usuario, "=response=00" + md5])

    def cmd(self, ruta, *extra):
        """Ejecuta un comando de solo lectura. Ej: cmd('/ip/service/print')."""
        filas, _ = self.talk([ruta] + list(extra))
        return filas
