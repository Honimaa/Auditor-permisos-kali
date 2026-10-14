#!/usr/bin/env bash
# Elimina el laboratorio creado por preparar_entorno.sh
set -euo pipefail
LAB="${1:-/opt/lab_auditoria}"
[[ $EUID -ne 0 ]] && { echo "Ejecute con sudo"; exit 1; }
rm -rf "$LAB" && echo "Laboratorio $LAB eliminado"
