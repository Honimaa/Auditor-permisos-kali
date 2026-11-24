# Auditor de permisos y configuraciones de riesgo en sistemas Linux

Proyecto de aula de Sistemas Operacionales, Politécnico Grancolombiano.
Autor: Juan Camilo Bejarano Chacón. Versión 1.1.0 (Entrega 4 + interfaz gráfica).

Herramienta de línea de comandos que recorre el sistema de archivos y reporta
configuraciones de permisos riesgosas, clasificadas por severidad y con una
recomendación de corrección. Solo reporta: no modifica permisos ni propietarios.

## Requisitos

- Linux (probado en Ubuntu 24.04 y Kali). No funciona en Windows ni macOS.
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
`--sin-html`, `--json ARCHIVO`, `--listas ARCHIVO`, `--registro ARCHIVO`, `--mantener-root` (no recomendado), `--color auto|si|no`, `--version`.

Códigos de salida: `3` = error de seguridad, `2` = hay hallazgos ALTA, `1` = otros hallazgos, `0` = sin hallazgos.

## Interfaz gráfica

```bash
sudo apt install python3-tk      # solo si Tkinter no está instalado
python3 auditor_gui.py           # SIN sudo: la ventana corre como usuario normal
```

La ventana permite elegir las carpetas, la severidad mínima y si la auditoría es completa (sudo).
Muestra el resumen por severidad, la tabla de hallazgos con colores, el detalle y la recomendación de
cada uno, un filtro por severidad y por ruta, la salida del auditor y un botón para abrir el reporte HTML.

La interfaz nunca tiene privilegios de root. Para la auditoría completa pide la contraseña de sudo y la
envía solo a `sudo -S`, que ejecuta `auditor.py` con la opción `--json`. El auditor suelta root después
del escaneo y escribe el JSON con permisos 0600 ya como el usuario, en una carpeta temporal privada
(0700) que la interfaz borra después de leerlo.

## Seguridad del propio auditor (Entrega 3)

| Mecanismo | Dónde | Qué hace |
|---|---|---|
| Menor privilegio | `auditor/seguridad.py` | Al ejecutarse con sudo, usa root solo para leer el disco. Terminado el escaneo llama a `initgroups`, `setgid` y `setuid` para volver al usuario que ejecutó sudo y comprueba que ya no puede recuperar root. |
| Reporte protegido | `auditor/seguridad.py` | El reporte se crea con permisos `0600` y `O_CREAT \| O_EXCL \| O_NOFOLLOW`: no sobrescribe archivos ni sigue enlaces simbólicos. Si la carpeta tiene una ACL por defecto, la máscara queda en `---` y no da acceso efectivo. |
| Registro de auditoría | `auditor/registro.py` | Cada ejecución agrega una línea JSON a `/var/log/auditor-permisos.log` (0600, solo agregar) con quién, cuándo, qué rutas, cuántos hallazgos y el SHA-256 del reporte. Sin sudo se usa `~/.local/state/auditor-permisos/registro.log`. Si el registro fue alterado (permisos, dueño o enlace), el auditor se detiene. |

Comprobar la integridad de un reporte: comparar `sha256sum reporte.html` con el valor `sha256_reporte` del registro.

## Listas base de SUID y SGID (Entrega 4)

Los binarios que normalmente tienen SUID o SGID están en `auditor/listas_base.conf`, no en el código.
El archivo tiene una sección `[comun]` y una por distribución; el auditor detecta la distribución con
`/etc/os-release` (`ID` e `ID_LIKE`) y usa, por ejemplo, `[comun]` + `[kali]` + `[debian]` en Kali.
Se puede usar otro archivo con `--listas ARCHIVO`.

Como este archivo decide qué SUID se consideran normales, se abre con `O_NOFOLLOW` y se revisa con
`fstat`: si es un enlace, si otros usuarios pueden escribirlo o si pertenece a otro usuario, el auditor
se detiene con el código 3.

## Reglas implementadas

| Regla | Detecta | Severidad |
|---|---|---|
| R01 | Archivo con permisos 777 | ALTA |
| R02 | Archivo con escritura para "otros" (ej. 666) | MEDIA |
| R03 | Directorio con escritura global sin sticky bit | ALTA |
| R04 | Binario SUID fuera de la lista base (`listas_base.conf`) | ALTA (dueño root) / MEDIA; BAJA si es esperado |
| R05 | Binario SGID fuera de la lista base (`listas_base.conf`) | MEDIA |
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

## Pruebas unitarias (28)

11 pruebas de reglas (`tests/test_reglas.py`), 9 de los mecanismos de seguridad (`tests/test_seguridad.py`)
6 del archivo de listas base (`tests/test_listas.py`) y 2 de la salida JSON (`tests/test_json.py`).

```bash
python3 -m unittest -v          # como usuario normal
sudo python3 -m unittest -v     # como root (incluye las pruebas de reducción de privilegios)
```

Algunas pruebas se omiten según quién las ejecute: la de UID inexistente y las dos de reducción de
privilegios necesitan root (y un usuario normal en el sistema), la de carpeta sin acceso necesita no ser
root y la de ACL necesita el paquete `acl`. Para cubrir las 28 hay que correr la suite con los dos usuarios.

## Historial de entregas

| Entrega | Versión | Contenido |
|---|---|---|
| 1 (semana 8) | — | Idea y alcance del proyecto |
| 2 (semana 10) | 0.2.0 | Avance funcional: escáner, reglas R01–R07, reporte en consola y HTML, 11 pruebas |
| 3 (semana 13) | 0.3.0 | Integración con seguridad: menor privilegio, reporte protegido, registro de auditoría, 20 pruebas |
| 4 (final) | 1.0.0 | Listas de SUID/SGID en archivo de configuración por distribución, validación en Kali, 26 pruebas |
| Sustentación | 1.1.0 | Interfaz gráfica con Tkinter y salida `--json`, 28 pruebas |

## Estructura

```
auditor_gui.py         interfaz gráfica (Tkinter); lanza auditor.py con sudo solo para el escaneo
auditor.py             CLI: argumentos y orquestación (escaneo → registro → soltar root → reporte)
auditor/escaner.py     recorrido con os.scandir + lstat (pila explícita, sin seguir enlaces)
auditor/reglas.py      reglas R01–R07
auditor/listas.py      lectura segura de las listas base según la distribución
auditor/listas_base.conf  listas de SUID/SGID esperados: [comun], [debian], [ubuntu], [kali]
auditor/usuarios.py    UID/GID válidos (pwd, grp)
auditor/reporte.py     salida en consola y construcción del HTML
auditor/seguridad.py   reducción de privilegios y escritura segura
auditor/registro.py    registro de auditoría de ejecuciones
auditor/modelos.py     estructuras de datos compartidas
lab/                   scripts del laboratorio y demostración del ataque
tests/                 pruebas unitarias
```
