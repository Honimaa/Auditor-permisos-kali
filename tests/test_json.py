"""Pruebas de la salida JSON que usa la interfaz gráfica."""

import json
import shutil
import os
import stat
import subprocess
import sys
import tempfile
import unittest

RAIZ_PROYECTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PruebasSalidaJson(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lab = os.path.join(self.tmp.name, "lab"); os.mkdir(self.lab)
        self.archivo = os.path.join(self.lab, "abierto.sh")
        with open(self.archivo, "w") as f:
            f.write("x")
        os.chmod(self.archivo, 0o777)
        self.json = os.path.join(self.tmp.name, "resultado.json")
        # copia de las listas base a nombre de quien corre la prueba (el clon puede ser de otro usuario)
        self.listas = os.path.join(self.tmp.name, "listas_base.conf")
        shutil.copyfile(os.path.join(RAIZ_PROYECTO, "auditor", "listas_base.conf"), self.listas)
        os.chmod(self.listas, 0o644)

    def tearDown(self):
        self.tmp.cleanup()

    def _ejecutar(self):
        cmd = [sys.executable, "auditor.py", self.lab, "--sin-html", "--json", self.json,
               "--registro", os.path.join(self.tmp.name, "registro.log"), "--listas", self.listas, "--color", "no"]
        entorno = {k: v for k, v in os.environ.items() if k not in ("SUDO_UID", "SUDO_GID", "SUDO_USER")}
        return subprocess.run(cmd, cwd=RAIZ_PROYECTO, env=entorno, capture_output=True, text=True, timeout=60)

    def test_json_con_hallazgos_y_permisos_0600(self):
        r = self._ejecutar()
        self.assertIn(r.returncode, (0, 1, 2), r.stderr)
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.json).st_mode))
        with open(self.json, encoding="utf-8") as f:
            datos = json.load(f)
        self.assertEqual(1, datos["resumen"]["ALTA"])
        self.assertEqual("R01-PERMISOS-777", datos["hallazgos"][0]["regla"])
        self.assertEqual(self.archivo, datos["hallazgos"][0]["ruta"])

    def test_json_no_sobrescribe_un_archivo_existente(self):
        open(self.json, "w").close()
        r = self._ejecutar()
        self.assertEqual(3, r.returncode)
        self.assertEqual(0, os.path.getsize(self.json))


if __name__ == "__main__":
    unittest.main()
