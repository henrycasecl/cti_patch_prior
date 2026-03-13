# MCP – Master Server

**Versión:** 1.0

Autor: Hernán Olmedo <biohack.cl@proton.me>
---

## Objetivo


---

## Cómo ejecutar el servidor

### Requisitos
- Node.js **18+**
- Docker y Docker Compose (**recomendado**)
- TypeScript (`tsc`)

### Ejecución básica
```bash
npm install
npm run build
npm run start

### Por defecto, el servidor expone el endpoint MCP en:

HTTP: http://0.0.0.0:6000/mcp
HTTPS (opcional): https://0.0.0.0:6001/mcp

## Consideraciones importantes

- Los recursos MCP (playbooks, matrices de riesgo, documentos) deben registrarse explícitamente en el servidor para estar disponibles.
- El servidor MCP no ejecuta acciones de seguridad, solo provee contexto, herramientas y procedimientos.
- La orquestación, el razonamiento y la decisión final recaen en el backend consumidor y el modelo de lenguaje.
- MCP es estricto en el uso de métodos, nombres y URIs (resources/list, resources/read, prompts/get, etc.).
- Diseñado para laboratorios, investigación y SOC internos. Se recomienda validación adicional antes de su uso en entornos productivos.
- El uso indebido de este software en producción sin pruebas ni controles adicionales es responsabilidad exclusiva del operador.

---

Derechos de autor y licencia

Este programa es software libre: usted puede redistribuirlo y/o modificarlo bajo los términos de la
GNU General Public License versión 3 (GPLv3), publicada por la Free Software Foundation.

© 2026 – MCP SOC Assistant Server