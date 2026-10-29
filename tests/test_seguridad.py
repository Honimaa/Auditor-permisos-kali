"""Pruebas de los mecanismos de seguridad (Entrega 3):
escritura segura del reporte, registro de auditoría y reducción de privilegios.
    python3 -m unittest -v tests.test_seguridad
La prueba de reducción de privilegios necesita root y un usuario normal en el sistema."""

import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from auditor.modelos import EstadisticasEscaneo, Hallazgo, Severidad
from auditor.registro import registrar_ejecucion, sha256_texto
from auditor.seguridad import ErrorSeguridad, escribir_archivo_seguro

RAIZ_PROYECTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _usuario_normal():
    for u in pwd.getpwall():
        if u.pw_uid >= 1000 and u.pw_name != "nobody" and u.pw_shell.endswith("sh"):
            return u
    return None


class PruebasEscrituraSegura(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_reporte_nace_con_0600_aunque_umask_sea_0(self):
        ruta = os.path.join(self.dir, "reporte.html")
        anterior = os.umask(0)
        try:
            escribir_archivo_seguro(ruta, "<html></html>")
        finally:
            os.umask(anterior)
        self.assertEqual(0o600, stat.S_IMODE(os.stat(ruta).st_mode))

    def test_no_sigue_enlaces_simbolicos(self):
        victima = os.path.join(self.dir, "victima.txt")
        with open(victima, "w") as f:
            f.write("original")
        cebo = os.path.join(self.dir, "reporte.html")
        os.symlink(victima, cebo)
        with self.assertRaises(ErrorSeguridad):
            escribir_archivo_seguro(cebo, "ataque")
        with open(victima) as f:
            self.assertEqual("original", f.read())

    @unittest.skipUnless(shutil.which("setfacl") and shutil.which("getfacl"), "requiere el paquete acl")
    def test_acl_por_defecto_no_da_acceso_efectivo(self):
        """Si la carpeta tiene una ACL por defecto que da rw a otro usuario, el reporte
        la hereda, pero como el modo es 0600 la máscara queda en --- y ese permiso
        no es efectivo."""
        os.chmod(self.dir, 0o755)
        r = subprocess.run(["setfacl", "-d", "-m", "u:nobody:rw", self.dir], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("el sistema de archivos no soporta ACL: " + r.stderr.strip())
        ruta = os.path.join(self.dir, "reporte.html")
        escribir_archivo_seguro(ruta, "x")
        acl = subprocess.run(["getfacl", "-p", ruta], capture_output=True, text=True).stdout
        self.assertIn("user:nobody:rw-", acl)    # la entrada se heredó...
        self.assertIn("mask::---", acl)          # ...pero la máscara la anula
        self.assertEqual(0o600, stat.S_IMODE(os.stat(ruta).st_mode))

    def test_no_sobrescribe_un_archivo_existente(self):
        ruta = os.path.join(self.dir, "reporte.html")
        escribir_archivo_seguro(ruta, "primero")
        with self.assertRaises(ErrorSeguridad):
            escribir_archivo_seguro(ruta, "segundo")
        with open(ruta) as f:
            self.assertEqual("primero", f.read())


class PruebasRegistro(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.tmp.name, "registro.log")
        self.est = EstadisticasEscaneo(archivos=10, directorios=2)
        self.hallazgos = [Hallazgo("R01-PERMISOS-777", Severidad.ALTA, "/x", "", "", "")]

    def tearDown(self):
        self.tmp.cleanup()

    def _registrar(self):
        return registrar_ejecucion(self.ruta, ["/x"], ["/x"], self.hallazgos, self.est,
                                   "r.html", sha256_texto("contenido"), "prueba")

    def test_agrega_una_linea_json_por_ejecucion(self):
        self._registrar()
        self._registrar()
        with open(self.ruta) as f:
            lineas = [json.loads(l) for l in f]
        self.assertEqual(2, len(lineas))
        self.assertEqual(1, lineas[0]["hallazgos"]["ALTA"])
        self.assertEqual(sha256_texto("contenido"), lineas[0]["sha256_reporte"])
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.ruta).st_mode))

    def test_rechaza_registro_con_permisos_abiertos(self):
        self._registrar()
        os.chmod(self.ruta, 0o666)          # alguien "abrió" el registro
        with self.assertRaises(ErrorSeguridad):
            self._registrar()

    def test_rechaza_registro_que_es_enlace(self):
        otro = os.path.join(self.tmp.name, "otro.log")
        open(otro, "w").close()
        os.symlink(otro, self.ruta)
        with self.assertRaises(ErrorSeguridad):
            self._registrar()


@unittest.skipUnless(os.geteuid() == 0 and _usuario_normal(), "requiere root y un usuario normal")
class PruebasMenorPrivilegio(unittest.TestCase):
    def test_reduce_privilegios_y_no_puede_volver_a_root(self):
        u = _usuario_normal()
        codigo = (
            "import os\n"
            "from auditor.seguridad import reducir_privilegios\n"
            f"reducir_privilegios({u.pw_uid}, {u.pw_gid}, {u.pw_name!r})\n"
            "try:\n"
            "    open('/etc/shadow').read(); print('LEYO_SHADOW')\n"
            "except PermissionError:\n"
            "    print('SHADOW_DENEGADO')\n"
            "print(os.getuid(), os.geteuid())\n"
        )
        r = subprocess.run([sys.executable, "-c", codigo], cwd=RAIZ_PROYECTO,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertIn("SHADOW_DENEGADO", r.stdout)
        self.assertIn(f"{u.pw_uid} {u.pw_uid}", r.stdout)

    def test_flujo_completo_con_sudo_simulado(self):
        """auditor.py ejecutado como root con SUDO_UID: el reporte debe quedar a nombre del usuario."""
        u = _usuario_normal()
        with tempfile.TemporaryDirectory() as d:
            os.chown(d, u.pw_uid, u.pw_gid)
            reporte = os.path.join(d, "r.html")
            registro = os.path.join(d, "registro.log")
            entorno = dict(os.environ, SUDO_UID=str(u.pw_uid), SUDO_GID=str(u.pw_gid), SUDO_USER=u.pw_name)
            r = subprocess.run([sys.executable, "auditor.py", "/etc/ssh", "--html", reporte,
                                "--registro", registro, "--color", "no"],
                               cwd=RAIZ_PROYECTO, env=entorno, capture_output=True, text=True, timeout=60)
            self.assertIn(r.returncode, (0, 1, 2), r.stderr)
            st_rep, st_reg = os.stat(reporte), os.stat(registro)
            self.assertEqual(u.pw_uid, st_rep.st_uid)          # reporte escrito ya sin root
            self.assertEqual(0o600, stat.S_IMODE(st_rep.st_mode))
            self.assertEqual(0, st_reg.st_uid)                 # registro escrito como root
            self.assertEqual(0o600, stat.S_IMODE(st_reg.st_mode))


if __name__ == "__main__":
    unittest.main()
