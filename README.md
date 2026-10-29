# Auditor de permisos y configuraciones de riesgo en sistemas Linux

Proyecto de aula de Sistemas Operacionales, Politécnico Grancolombiano.
Autor: Juan Camilo Bejarano Chacón. Versión 0.3.0 (Entrega 3: integración con seguridad).

Herramienta de línea de comandos que recorre el sistema de archivos y reporta
configuraciones de permisos riesgosas, clasificadas por severidad y con una
recomendación de corrección. Solo reporta: no modifica permisos ni propietarios.

## Requisitos

- Linux (probado en Ubuntu 24.04; pensado también para Kali). No funciona en Windows ni macOS.
- Python 3.8 o superior, solo biblioteca estándar: no hay que instalar dependencias.
- Opcional: paquete `acl` (`setfacl`/`getfacl`) para la prueba de ACL y `strace` para ver las llamadas al sistema.

## Uso

```bash
git clone <url-del-repositorio> && cd auditor-permisos
sudo python3 auditor.py /etc /home /usr/bin            # consola + reporte_FECHA.html
sudo python3 auditor.py / --min-severidad ALTA --sin-html
python3 auditor.py --help
```

Opciones principales: `--excluir`, `--profundidad`, `--mismo-fs`, `--min-severidad`, `--html ARCHIVO`,
`--sin-html`, `--registro ARCHIVO`, `--mantener-root` (no recomendado), `--color auto|si|no`, `--version`.

Códigos de salida: `3` = error de seguridad, `2` = hay hallazgos ALTA, `1` = otros hallazgos, `0` = sin hallazgos.

## Seguridad del propio auditor (Entrega 3)

| Mecanismo | Dónde | Qué hace |
|---|---|---|
| Menor privilegio | `auditor/seguridad.py` | Al ejecutarse con sudo, usa root solo para leer el disco. Terminado el escaneo llama a `initgroups`, `setgid` y `setuid` para volver al usuario que ejecutó sudo y comprueba que ya no puede recuperar root. |
| Reporte protegido | `auditor/seguridad.py` | El reporte se crea con permisos `0600` y `O_CREAT \| O_EXCL \| O_NOFOLLOW`: no sobrescribe archivos ni sigue enlaces simbólicos. Si la carpeta tiene una ACL por defecto, la máscara queda en `---` y no da acceso efectivo. |
| Registro de auditoría | `auditor/registro.py` | Cada ejecución agrega una línea JSON a `/var/log/auditor-permisos.log` (0600, solo agregar) con quién, cuándo, qué rutas, cuántos hallazgos y el SHA-256 del reporte. Sin sudo se usa `~/.local/state/auditor-permisos/registro.log`. Si el registro fue alterado (permisos, dueño o enlace), el auditor se detiene. |

Comprobar la integridad de un reporte: comparar `sha256sum reporte.html` con el valor `sha256_reporte` del registro.

## Reglas implementadas

| Regla | Detecta | Severidad |
|---|---|---|
| R01 | Archivo con permisos 777 | ALTA |
| R02 | Archivo con escritura para "otros" (ej. 666) | MEDIA |
| R03 | Directorio con escritura global sin sticky bit | ALTA |
| R04 | Binario SUID fuera de la lista base | ALTA (dueño root) / MEDIA; BAJA si es esperado |
| R05 | Binario SGID fuera de la lista base | MEDIA |
| R06 | UID o GID inexistente en /etc/passwd o /etc/group | MEDIA / BAJA |
| R07 | /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow, /etc/sudoers y el registro del auditor con permisos de más | ALTA |

## Laboratorio de pruebas (solo en una máquina virtual)

```bash
# Tome una instantánea de la VM antes de empezar.
sudo bash lab/preparar_entorno.sh            # crea /opt/lab_auditoria con fallas sembradas
sudo python3 auditor.py /opt/lab_auditoria
sudo bash lab/ataque_enlace.sh               # demostración del ataque por enlace simbólico
sudo bash lab/limpiar_entorno.sh
```

## Pruebas unitarias (20)

11 pruebas de reglas (`tests/test_reglas.py`) y 9 de los mecanismos de seguridad (`tests/test_seguridad.py`).

```bash
python3 -m unittest -v          # como usuario normal
sudo python3 -m unittest -v     # como root (incluye las pruebas de reducción de privilegios)
```

Algunas pruebas se omiten según quién las ejecute: la de UID inexistente y las dos de reducción de
privilegios necesitan root (y un usuario normal en el sistema), la de carpeta sin acceso necesita no ser
root y la de ACL necesita el paquete `acl`. Para cubrir las 20 hay que correr la suite con los dos usuarios.

## Historial de entregas

| Entrega | Versión | Contenido |
|---|---|---|
| 1 (semana 8) | — | Idea y alcance del proyecto |
| 2 (semana 10) | 0.2.0 | Avance funcional: escáner, reglas R01–R07, reporte en consola y HTML, 11 pruebas |
| 3 (semana 13) | 0.3.0 | Integración con seguridad: menor privilegio, reporte protegido, registro de auditoría, 20 pruebas |

## Estructura

```
auditor.py             CLI: argumentos y orquestación (escaneo → registro → soltar root → reporte)
auditor/escaner.py     recorrido con os.scandir + lstat (pila explícita, sin seguir enlaces)
auditor/reglas.py      reglas R01–R07 y listas base de SUID/SGID
auditor/usuarios.py    UID/GID válidos (pwd, grp)
auditor/reporte.py     salida en consola y construcción del HTML
auditor/seguridad.py   reducción de privilegios y escritura segura
auditor/registro.py    registro de auditoría de ejecuciones
auditor/modelos.py     estructuras de datos compartidas
lab/                   scripts del laboratorio y demostración del ataque
tests/                 pruebas unitarias
```
