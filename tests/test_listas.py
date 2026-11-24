"""Pruebas del archivo de listas base de SUID/SGID (Entrega 4)."""

import os
import tempfile
import unittest

from auditor.listas import RUTA_POR_DEFECTO, cargar_listas, detectar_distribucion
from auditor.modelos import Severidad
from auditor.reglas import Contexto, regla_suid_sgid
from auditor.modelos import EntradaArchivo
from auditor.seguridad import ErrorSeguridad
from auditor.usuarios import BaseUsuarios

CONF = """[comun]
suid = /usr/bin/passwd
sgid = /usr/bin/crontab
[kali]
suid = /usr/bin/solo_kali
[ubuntu]
sgid = /usr/bin/solo_ubuntu
"""


class PruebasListas(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.tmp.name, "listas.conf")
        with open(self.ruta, "w") as f:
            f.write(CONF)
        os.chmod(self.ruta, 0o644)

    def tearDown(self):
        self.tmp.cleanup()

    def test_usa_comun_y_la_distribucion_detectada(self):
        suid, sgid, usadas = cargar_listas(self.ruta, distros=["kali", "debian"])
        self.assertEqual(["comun", "kali"], usadas)
        self.assertEqual({"/usr/bin/passwd", "/usr/bin/solo_kali"}, set(suid))
        self.assertNotIn("/usr/bin/solo_ubuntu", sgid)

    def test_detecta_id_e_id_like(self):
        osr = os.path.join(self.tmp.name, "os-release")
        with open(osr, "w") as f:
            f.write('PRETTY_NAME="Kali GNU/Linux Rolling"\nID=kali\nID_LIKE=debian\n')
        self.assertEqual(("kali", "debian"), detectar_distribucion(osr))

    def test_rechaza_archivo_escribible_por_otros(self):
        os.chmod(self.ruta, 0o666)
        with self.assertRaises(ErrorSeguridad):
            cargar_listas(self.ruta, distros=[])

    def test_rechaza_enlace_simbolico(self):
        enlace = os.path.join(self.tmp.name, "enlace.conf")
        os.symlink(self.ruta, enlace)
        with self.assertRaises(ErrorSeguridad):
            cargar_listas(enlace, distros=[])

    def test_binario_de_la_lista_es_baja(self):
        suid, sgid, _ = cargar_listas(self.ruta, distros=["kali"])
        ctx = Contexto(BaseUsuarios(), suid_esperados=suid, sgid_esperados=sgid)
        e = EntradaArchivo(ruta="/usr/bin/solo_kali", modo=0o104755, uid=0, gid=0, es_directorio=False)
        h = regla_suid_sgid(e, ctx)
        self.assertEqual([Severidad.BAJA], [x.severidad for x in h])

    def test_archivo_del_proyecto_es_valido(self):
        suid, sgid, usadas = cargar_listas(RUTA_POR_DEFECTO, distros=["kali", "debian"])
        self.assertIn("/usr/bin/passwd", suid)
        self.assertEqual(["comun", "kali", "debian"], usadas)


if __name__ == "__main__":
    unittest.main()
