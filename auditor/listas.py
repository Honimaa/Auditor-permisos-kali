"""Listas base de binarios SUID y SGID esperados (Entrega 4).

Las listas ya no están escritas en el código: se leen de un archivo de
configuración (listas_base.conf) con una sección [comun] y una sección por
distribución. La distribución se detecta con /etc/os-release (ID e ID_LIKE),
así en Kali se usan [comun] + [kali] + [debian] y en Ubuntu [comun] + [ubuntu] + [debian].

Como el archivo decide qué binarios SUID se consideran normales, quien pueda
modificarlo podría esconder un SUID malicioso. Por eso se abre sin seguir enlaces
y se rechaza si otros usuarios pueden escribir en él.
"""

import configparser
import grp
import os
import pwd
import stat
from typing import FrozenSet, Iterable, List, Optional, Tuple

from .seguridad import ErrorSeguridad, usuario_invocador

RUTA_POR_DEFECTO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "listas_base.conf")


def detectar_distribucion(ruta_os_release: str = "/etc/os-release") -> Tuple[str, ...]:
    """Devuelve el ID de la distribución seguido de su ID_LIKE. Ej.: ('kali', 'debian')."""
    datos = {}
    try:
        with open(ruta_os_release, encoding="utf-8") as f:
            for linea in f:
                if "=" in linea:
                    clave, valor = linea.rstrip("\n").split("=", 1)
                    datos[clave] = valor.strip().strip('"').strip("'")
    except OSError:
        return ()
    ids = [datos.get("ID", "")] + datos.get("ID_LIKE", "").split()
    return tuple(i.lower() for i in ids if i)


def _es_grupo_privado(st: os.stat_result) -> bool:
    """True si el grupo del archivo es el grupo personal de su dueño (mismo nombre, sin
    otros miembros). En ese caso el permiso de escritura del grupo no le da acceso a nadie más."""
    try:
        dueno = pwd.getpwuid(st.st_uid)
        grupo = grp.getgrgid(st.st_gid)
    except KeyError:
        return False
    return dueno.pw_gid == st.st_gid and grupo.gr_name == dueno.pw_name and not grupo.gr_mem


def _verificar_archivo(st: os.stat_result, ruta: str) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise ErrorSeguridad(f"el archivo de listas '{ruta}' no es un archivo regular")
    if st.st_mode & stat.S_IWOTH:
        raise ErrorSeguridad(f"el archivo de listas '{ruta}' lo puede modificar cualquier usuario; "
                             f"corrija con chmod o-w")
    if st.st_mode & stat.S_IWGRP and not _es_grupo_privado(st):
        raise ErrorSeguridad(f"el archivo de listas '{ruta}' lo pueden modificar otros miembros de su grupo; "
                             f"corrija con chmod g-w")
    permitidos = {0, os.getuid()}
    invocador = usuario_invocador()
    if invocador:
        permitidos.add(invocador[0])
    if st.st_uid not in permitidos:
        raise ErrorSeguridad(f"el archivo de listas '{ruta}' pertenece a otro usuario (UID {st.st_uid})")


def _rutas(valor: str) -> List[str]:
    rutas = valor.split()
    for r in rutas:
        if not r.startswith("/"):
            raise ErrorSeguridad(f"ruta no absoluta en el archivo de listas: '{r}'")
    return rutas


def cargar_listas(ruta: Optional[str] = None, distros: Optional[Iterable[str]] = None
                  ) -> Tuple[FrozenSet[str], FrozenSet[str], List[str]]:
    """Lee el archivo y devuelve (suid_esperados, sgid_esperados, secciones_usadas)."""
    ruta = ruta or RUTA_POR_DEFECTO
    distros = detectar_distribucion() if distros is None else tuple(distros)
    try:
        fd = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise ErrorSeguridad(f"no se encontró el archivo de listas '{ruta}'")
    except OSError as e:   # ELOOP: la ruta es un enlace simbólico
        raise ErrorSeguridad(f"no se pudo abrir el archivo de listas '{ruta}' de forma segura: {e.strerror}")
    with os.fdopen(fd, encoding="utf-8") as f:
        _verificar_archivo(os.fstat(f.fileno()), ruta)   # se revisa el archivo ya abierto
        contenido = f.read()

    cfg = configparser.ConfigParser(interpolation=None)
    try:
        cfg.read_string(contenido, source=ruta)
    except configparser.Error as e:
        raise ErrorSeguridad(f"el archivo de listas '{ruta}' tiene un error de formato: {e}")

    suid, sgid, usadas = set(), set(), []
    for seccion in ["comun", *distros]:
        if seccion in usadas or not cfg.has_section(seccion):
            continue
        usadas.append(seccion)
        suid.update(_rutas(cfg.get(seccion, "suid", fallback="")))
        sgid.update(_rutas(cfg.get(seccion, "sgid", fallback="")))
    return frozenset(suid), frozenset(sgid), usadas
