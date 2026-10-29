"""Consulta de usuarios y grupos válidos del sistema (/etc/passwd y /etc/group).

Se cargan una sola vez en diccionarios para que verificar si un UID existe
sea O(1); consultar pwd.getpwuid() por cada archivo era mucho más lento.
"""

import grp
import pwd


class BaseUsuarios:
    def __init__(self):
        self.uids = {}
        self.gids = {}
        for u in pwd.getpwall():
            self.uids[u.pw_uid] = u.pw_name
        for g in grp.getgrall():
            self.gids[g.gr_gid] = g.gr_name

    def existe_uid(self, uid: int) -> bool:
        return uid in self.uids

    def existe_gid(self, gid: int) -> bool:
        return gid in self.gids

    def nombre_usuario(self, uid: int) -> str:
        return self.uids.get(uid, f"UID {uid} (inexistente)")

    def nombre_grupo(self, gid: int) -> str:
        return self.gids.get(gid, f"GID {gid} (inexistente)")
