# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Jose Liria
- **Repositorio:** https://github.com/Liria18/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04.5 LTS sobre WSL2 (Windows) · Python 3.12.3

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41–42 | **Inyección SQL** (CWE-89): la consulta se construye concatenando con `+` el nombre del cliente, así que el dato puede cambiar el significado de la orden SQL. | Parámetro `cliente` de la URL `/reportes?cliente=…` (`servicio.py`, l. 41–42) | `cursor.execute(query)` (`reporte_auditoria.py`, l. 42) |
| 2 | `convertir_a_pdf` | 50–51 | **Inyección de comandos del sistema operativo** (CWE-78): el nombre de archivo se pega en una orden que ejecuta la shell; un `;` o `&` permite encadenar otros comandos. No hay validación real (el `ValueError` que captura `servicio.py` nunca se lanza). | Parámetro `archivo` de la URL `/convertir?archivo=…` (`servicio.py`, l. 53–55) | `os.system(comando)` (`reporte_auditoria.py`, l. 51) |
| 3 | `cargar_configuracion` | 33 | **Deserialización insegura de YAML** (CWE-502): `yaml.Loader` (Loader completo) puede construir objetos de Python arbitrarios con etiquetas como `!!python/object/apply`, lo que permite ejecutar código. Debería usarse `yaml.safe_load`. | Contenido del archivo `config.yaml` abierto en la l. 29 (quien pueda modificarlo controla el dato) | `yaml.load(f, Loader=yaml.Loader)` (`reporte_auditoria.py`, l. 33) |
| 4 | `hash_password_legacy` | 57 | **Hash débil para contraseñas** (CWE-327 / CWE-916): MD5 es rapidísimo y está roto, y se usa **sin sal**, así que dos usuarios con la misma contraseña tienen el mismo hash y se puede atacar con tablas precalculadas o fuerza bruta. | Parámetro `password` de la función | `hashlib.md5(password.encode()).hexdigest()` (`reporte_auditoria.py`, l. 57) |
| 5 | Constantes del módulo | 21–22 | **Secretos escritos en el código** (CWE-798): `NOTIFICATION_API_KEY` y `SMTP_PASSWORD` están en texto plano en un repositorio **público**, y quedan en el historial de Git aunque se borren después. | El propio código fuente versionado (cualquiera que lea el repositorio o su historial) | Exposición en el repositorio; la API key se usa en `notificar_cliente` (l. 62) |

**Síntoma observado (C.2):** `GET /reportes?cliente=o'brien_ltd` devuelve **500 Internal Server Error**, y la terminal muestra `sqlite3.OperationalError: near "brien_ltd": syntax error` (traza: `servicio.py` l. 42 → `reporte_auditoria.py` l. 42, `cursor.execute(query)`). Un apóstrofo legítimo cierra la cadena SQL antes de tiempo: los datos se mezclan con la orden, que es la raíz de la inyección SQL.

**Impacto en el negocio:**

1. **Inyección SQL:** un usuario podría leer los reportes de auditoría de **todos los clientes** (por ejemplo, con `' OR '1'='1`) o alterarlos, lo que supone una fuga de datos confidenciales de terceros y un incumplimiento del RGPD y de los contratos con los clientes.
2. **Inyección de comandos:** cualquiera con acceso a `/convertir` podría **ejecutar comandos en el servidor** con los permisos del servicio: leer la base de datos y los secretos, borrar archivos o usar la máquina como punto de entrada a la red interna.
3. **YAML inseguro:** quien consiga modificar `config.yaml` (otro proceso, un despliegue comprometido o un compañero con acceso) obtiene **ejecución de código** al arrancar el servicio, con el mismo impacto que la fila 2.
4. **MD5 sin sal:** si se filtra la tabla de contraseñas del sistema legado, se recuperarían rápidamente las **contraseñas de los clientes**, que muchos reutilizan en otros servicios.
5. **Secretos en el código:** cualquiera en internet puede usar la **API de notificaciones** a nombre de la empresa (suplantación, spam o coste) y la **cuenta SMTP** para enviar correos fraudulentos que parecen legítimos. Hay que **rotar ambas credenciales**: borrarlas del código no basta.

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ | ✗ | ✓ taint: *SQL Injection* | ✓ `pythonsecurity:S3649` (l. 42) | ✓ `py/sql-injection` (l. 42) | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | ✗ | ✓ taint: *Command Injection* | ✓ `pythonsecurity:S2076` (l. 51) | ✓ `py/command-line-injection` (l. 51) | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ `avoid-pyyaml-load` (l. 33) | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ `python:S4790` (l. 57) | ✓ `python:S4790` (l. 57) | ✓ `python:S4790` (l. 57) | ✓ `py/weak-sensitive-data-hashing` (l. 57) | ✓ `insecure-hash-algorithm-md5` + `md5-used-as-password` (l. 57) | n/a |
| H5 Clave de API escrita en el código | ✓ | ✗ | ✗ | ✗ | ✗ (solo `py/clear-text-logging-sensitive-data`, l. 62: detecta que se imprime, no que esté escrita) | ✗ | ✗ (0 secretos) |
| H6 Contraseña SMTP escrita en el código | ✓ | ✓ `python:S2068` (l. 22) | ✓ `python:S2068` + `secrets:S7552` (l. 22) | ✓ `python:S2068` + `secrets:S7552` (l. 22) | ✗ | ✗ | ✗ (0 secretos) |

**Hallazgos extra de las herramientas (no estaban en la auditoría manual):**
- SonarQube Cloud `python:S4502` en `app/servicio.py` l. 25: protección CSRF desactivada en Flask (revisar si aplica: la API solo usa GET).
- CodeQL `py/clear-text-logging-sensitive-data` en `app/reporte_auditoria.py` l. 62: `notificar_cliente` imprime parte de `NOTIFICATION_API_KEY` en el log.

**Conclusión de la matriz:** **ninguna herramienta lo detectó todo.** La que más cubre es SonarQube (Connected Mode y Cloud, 4 de 6), pero no ve el YAML inseguro (H3), que solo encontró Semgrep; Semgrep, a su vez, no ve las inyecciones H1 y H2 (sin *taint analysis* entre archivos), que sí ven SonarQube Cloud y CodeQL. La **clave de API (H5) no la detectó ninguna herramienta**: solo la auditoría manual. Las reglas de secretos se fijan en nombres como `PASSWORD` (SonarQube vio H6) o en formatos de proveedores conocidos (Trivy no vio ninguna de las dos). Sin conexión, SonarQube for IDE solo vio 2 de 6; conectado, 4 de 6, porque el *taint analysis* lo calcula el servidor. Al revés, las herramientas encontraron dos cosas que yo no anoté (S4502 CSRF y el *log* de la clave en la l. 62). Conclusión: un escaneo limpio no demuestra que no haya problemas; hay que **combinar capas** (editor, hook, pipeline, SCA y revisión humana), porque lo que se escapa de una lo atrapa otra.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2 (`flask`, `pyyaml`) |
| Componentes Python en el SBOM | 9 (`blinker` 1.7.0, `click` 8.1.7, `colorama` 0.4.6, `flask` 3.0.0, `itsdangerous` 2.1.2, `jinja2` 3.1.2, `markupsafe` 3.0.3, `pyyaml` 6.0.3, `werkzeug` 3.0.1): **7 transitivas por cada 2 directas** (efecto iceberg ×4,5) |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 4 de tipo `github-action` (`actions/checkout` v6, `SonarSource/sonarqube-scan-action` v7, `github/codeql-action/init` v4, `github/codeql-action/analyze` v4): salen de `.github/workflows/cadena-suministro.yml`; el pipeline también es cadena de suministro |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | `bomFormat`: CycloneDX · `specVersion`: 1.7 |

**Nota sobre el «antes»:** el PR #23 de Dependabot se fusionó antes de esta parte, así que el SBOM y los escaneos del «antes» (`sbom.cyclonedx.json`, `grype-antes.txt`, `trivy-antes.txt`) se generaron con el `requirements.txt` original del commit de importación `3cce46e` (`git show 3cce46e:requirements.txt`), restaurando después el actual.

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-34069 / GHSA-2g68-c3qc-8985 | High | 3.0.3 | No: afecta solo al **depurador interactivo** de Werkzeug, y el servicio arranca con `debug=False` (`app/servicio.py` l. 64). | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) **+ VEX `not_affected`** |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49767 / GHSA-q34m-jh98-gwm2 | Medium | 3.0.6 | No: agotamiento de recursos al parsear **ficheros en formularios multipart**; la API solo usa `GET` con `request.args` (`servicio.py` l. 41, 53), nunca `request.form`/`request.files`. | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49766 / GHSA-f9vj-2wh5-fj8j | Medium | 3.0.6 | No: fallo de `safe_join()` con nombres de dispositivo especiales **de Windows**; ReportAudit no usa `safe_join`/`send_from_directory` (ver `grep` en `app/`) y se ejecuta en Linux (WSL2 y GitHub Actions). | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2025-66221 / GHSA-hgf8-39gv-g3f2 | Medium | 3.1.4 | No: fallo de `safe_join()` con nombres de dispositivo especiales **de Windows**; ReportAudit no usa `safe_join`/`send_from_directory` (ver `grep` en `app/`) y se ejecuta en Linux (WSL2 y GitHub Actions). | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-21860 / GHSA-87hc-h4r5-73f7 | Medium | 3.1.5 | No: fallo de `safe_join()` con nombres de dispositivo especiales **de Windows**; ReportAudit no usa `safe_join`/`send_from_directory` (ver `grep` en `app/`) y se ejecuta en Linux (WSL2 y GitHub Actions). | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-27199 / GHSA-29vq-49wr-vm6x | Medium | 3.1.6 | No: fallo de `safe_join()` con nombres de dispositivo especiales **de Windows**; ReportAudit no usa `safe_join`/`send_from_directory` (ver `grep` en `app/`) y se ejecuta en Linux (WSL2 y GitHub Actions). | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-102598 / GHSA-g6x2-hccm-hh4m | Medium | 3.1.9 | No: fallo de `safe_join()` con nombres de dispositivo especiales **de Windows**; ReportAudit no usa `safe_join`/`send_from_directory` (ver `grep` en `app/`) y se ejecuta en Linux (WSL2 y GitHub Actions). | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-22195 / GHSA-h5c8-rqwp-cp95 | Medium | 3.1.3 | No: ReportAudit **no renderiza plantillas**: todas las respuestas son `jsonify` (`app/servicio.py` l. 31, 43, 57–58). Tampoco usa el filtro `xmlattr`. | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-34064 / GHSA-h75v-3vvj-5mfj | Medium | 3.1.4 | No: ReportAudit **no renderiza plantillas**: todas las respuestas son `jsonify` (`app/servicio.py` l. 31, 43, 57–58). Tampoco usa el filtro `xmlattr`. | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56201 / GHSA-gmj6-6f8f-6699 | Medium | 3.1.5 | No: ReportAudit **no renderiza plantillas**: todas las respuestas son `jsonify` (`app/servicio.py` l. 31, 43, 57–58). El ataque exige controlar el nombre y el contenido de una plantilla. | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56326 / GHSA-q2x7-8rv6-6q7h | Medium | 3.1.5 | No: ReportAudit **no renderiza plantillas**: todas las respuestas son `jsonify` (`app/servicio.py` l. 31, 43, 57–58). No usa el *sandbox* (`SandboxedEnvironment`). | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7 | Medium | 3.1.6 | No: ReportAudit **no renderiza plantillas**: todas las respuestas son `jsonify` (`app/servicio.py` l. 31, 43, 57–58). No usa el *sandbox* ni el filtro `attr`. | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |
| flask | 3.0.0 | **Directa** (`# via -r requirements.in`) | CVE-2026-27205 / GHSA-68rp-wp8r-4726 | Low | 3.1.3 | No: afecta a la cabecera `Vary: Cookie` al usar `session`; ReportAudit **no usa `session`** ni cookies: es una API JSON sin estado. | Actualizar (PR #23 de Dependabot, ya fusionado: coste bajo) |

**Dependabot (Parte I.3):** 13 alertas sobre el `requirements.txt` original: werkzeug 3.0.1 (7: CVE-2024-34069 *high*, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598), jinja2 3.1.2 (5: CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516) y flask 3.0.0 (1: CVE-2026-27205 *low*). Werkzeug y Jinja2 son **transitivas** (`# via flask`): nadie las eligió, llegan con Flask (efecto iceberg). Flask es **directa** (`# via -r requirements.in`). El PR agrupado #23 (`parches-de-seguridad`) las corrigió todas.

**Comparación con Dependabot:** coinciden al 100 %: las mismas **13** vulnerabilidades con los mismos GHSA (Dependabot #1–#13 = las 13 filas de Grype). Diferencias: Dependabot analiza el manifiesto `requirements.txt` de la rama `main` y abre el PR de corrección; Grype analiza el **SBOM** (sirve para cualquier versión archivada, sin tocar el código) y añade **EPSS** y **RISK** para priorizar (solo CVE-2024-34069 es *High*, EPSS 3,4 %, percentil 89). Hoy Dependabot muestra 0 abiertas porque el PR #23 ya actualizó `main`; el escaneo de Grype es del `requirements.txt` original.

**Documento VEX:** [`docs/evidencias/reportaudit.openvex.json`](evidencias/reportaudit.openvex.json) — CVE-2024-34069 (GHSA-2g68-c3qc-8985) en `pkg:pypi/werkzeug@3.0.1`: `not_affected` / `vulnerable_code_not_in_execute_path`, porque solo afecta al depurador interactivo de Werkzeug y ReportAudit arranca con `debug=False` (`app/servicio.py` l. 64). Aun así se actualizó (PR #23): el VEX no es excusa para no actualizar.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 (`avoid-pyyaml-load`, `insecure-hash-algorithm-md5`, `md5-used-as-password`) | 0 (`pre-commit run --all-files` → **Passed**) |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 (`py/sql-injection`, `py/command-line-injection`, `py/weak-sensitive-data-hashing`, `py/clear-text-logging-sensitive-data`) | 0 (las 4 en *Closed* como **Fixed** tras fusionar el PR #25) |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 (4 BLOCKER/MAJOR en `reporte_auditoria.py` + S4790 y S4502) | 0 abiertas (5 corregidas por el PR #25; `python:S4502` CSRF **aceptada** con justificación: API de solo lectura con `GET`, sin cookies ni sesiones) |
| Security Hotspots por revisar en SonarQube Cloud | 0 (en SonarQube Cloud los *Security Hotspots* están deprecados: S2068, S4790 y S4502 aparecen como vulnerabilidades dentro de las 6) | 0 (concepto deprecado; S4502 revisada como issue y aceptada) |
| Vulnerabilidades de Grype sobre el SBOM | 13 (1 High, 11 Medium, 1 Low; werkzeug ×7, jinja2 ×5, flask ×1) | 0 (`grype-despues.txt`: *No vulnerabilities found*; Trivy también 0 en `trivy-despues.txt`) |
| Alertas abiertas de Dependabot | 13 (werkzeug ×7 y jinja2 ×5, transitivas `# via flask`; flask ×1, directa `# via -r requirements.in`) | 0 (las 13 en estado *fixed* tras fusionar el PR #23 de Dependabot) |

**Parte M.5 — ¿Por qué el PR de código (#25) no cerró las alertas de Dependabot, y el de Dependabot (#23) no cerró las de CodeQL?** Porque son **categorías distintas que se corrigen en sitios distintos**. Las alertas de CodeQL (SAST) señalan fallos en **nuestro código** (`app/reporte_auditoria.py`) y solo desaparecen cuando el código cambia: el PR #23 solo tocó versiones en `requirements.txt`. Las alertas de Dependabot (SCA) señalan **versiones vulnerables de dependencias** y solo se cierran cuando cambia el lockfile: el PR #25 no tocó `requirements.txt`. Cada herramienta reanaliza `main` y cierra sola lo que ya no encuentra.

---

## Preguntas de comprobación (Sección 7 de la guía)

1. **Windows** aloja VS Code (la interfaz), el navegador, la descarga del zip y el Word de evidencias. **Ubuntu (WSL2)** aloja todo el proyecto (`~/reportaudit-lab`): Python y su `venv`, Git, `pre-commit`/Semgrep, Syft, Grype, Trivy y la base de datos; ahí se ejecutan todos los comandos. **GitHub** aloja la copia pública del repositorio, los Issues y PR, el pipeline de Actions, los secretos, la protección de `main`, Dependabot y los resultados de CodeQL (y SonarQube Cloud, el panel de análisis). Se trabaja en Ubuntu porque las herramientas y los *runners* de GitHub Actions son Linux: lo que funciona en mi terminal funciona igual en el pipeline, y además Grype/Trivy no tienen versión para Windows ARM.
2. Una dependencia **directa** es la que el equipo eligió y declaró en `requirements.in`; una **transitiva** llega arrastrada por otra sin que nadie la pidiera. En `requirements.txt`, `flask==3.0.0` tiene `# via -r requirements.in` (directa) y `werkzeug==3.0.1` tiene `# via flask` (transitiva); ambas aparecen en `sbom.cyclonedx.json` como `pkg:pypi/flask@3.0.0` y `pkg:pypi/werkzeug@3.0.1`. Con 2 directas el SBOM tiene 9 paquetes de Python, y 12 de las 13 vulnerabilidades estaban en transitivas (Werkzeug y Jinja2): el iceberg.
3. El **source** es el punto por donde entra un dato que controla alguien de fuera; el **sink** es la instrucción peligrosa donde ese dato acaba actuando. Ejemplo: en `servicio.py` l. 41 `cliente = request.args.get("cliente", "")` (source) se pasa en la l. 42 a `buscar_reportes_cliente`, que en `reporte_auditoria.py` l. 41 lo concatenaba en la consulta y en la l. 42 lo ejecutaba con `cursor.execute(query)` (sink).
4. Porque la consulta se construía pegando el nombre dentro de comillas: `... WHERE cliente = 'o'brien_ltd'`. El apóstrofo cerraba la cadena antes de tiempo y `brien_ltd'` pasaba a leerse como parte de la orden SQL, que dejaba de ser válida (`sqlite3.OperationalError: near "brien_ltd"`). Si un dato inocente puede cambiar la estructura de la consulta, un dato malicioso (`' OR '1'='1`) también: datos y órdenes estaban mezclados. Tras el PR #25 (consulta parametrizada) `o'brien_ltd` devuelve 200.
5. El hook actúa **en mi equipo y antes de que el commit exista**: es la barrera más temprana (*shift-left*) y el código inseguro ni siquiera llega a GitHub (lo comprobé en H.3: el commit de prueba fue bloqueado). Además detectó el YAML inseguro (H3), que no vieron SonarQube ni CodeQL. Pero no basta solo: vive en la copia local (quien no ejecute `pre-commit install` no lo tiene), se puede saltar con `--no-verify` y analiza archivo a archivo sin *taint analysis* entre archivos (no vio H1 ni H2). Por eso se combina con el pipeline obligatorio en la nube.
6. No es un error: cada herramienta usa técnicas y reglas distintas. Según mi matriz, SonarQube Cloud y CodeQL ven las inyecciones H1/H2 gracias al *taint analysis* entre `servicio.py` y `reporte_auditoria.py`, pero no el YAML (H3); Semgrep ve H3 y H4 pero no H1/H2; las reglas de secretos dependen del nombre de la variable (`PASSWORD`, H6) o de formatos de proveedor, y por eso **la API key (H5) solo la encontré yo a mano** y Trivy no vio ningún secreto. Ninguna lo detectó todo: hay que combinar capas.
7. Porque son categorías distintas que se corrigen en sitios distintos. CodeQL (SAST) señala fallos en **nuestro código** y solo los cierra cuando el código cambia; el PR #23 de Dependabot solo tocó versiones en `requirements.txt`. Dependabot (SCA) señala **versiones vulnerables de dependencias** y solo las cierra cuando cambia el lockfile; el PR #25 no tocó `requirements.txt`. Cada herramienta reanaliza `main` y cierra sola lo que ya no encuentra.
8. Borrar la línea solo quita el secreto de la versión actual: sigue en el **historial de Git** (commit `3cce46e`), en clones, *forks* y cachés, y el repositorio es público, así que hay que darlo por comprometido. Corregir de verdad es **rotar** la credencial en el proveedor (invalidar la antigua y emitir una nueva) y sacarla del código hacia variables de entorno o un gestor de secretos (`REPORTAUDIT_NOTIFICATION_API_KEY`, `REPORTAUDIT_SMTP_PASSWORD`), como se declaró en el PR #25.
9. Ignorar una alerta no deja rastro: nadie sabe quién decidió, cuándo ni por qué, y vuelve a aparecer y a ignorarse. Un VEX es una **declaración revisable y legible por máquinas**: qué vulnerabilidad, en qué componente exacto (purl), con qué estado, con qué justificación estándar, quién y cuándo. Mi VEX declara CVE-2024-34069 en `pkg:pypi/werkzeug@3.0.1` como `not_affected` / `vulnerable_code_not_in_execute_path`, porque solo afecta al depurador interactivo y ReportAudit arranca con `debug=False` (`app/servicio.py` l. 64). Aun así se actualizó Werkzeug: el VEX no sustituye a actualizar cuando es barato.
10. Descarga una **versión fijada** de Syft, Grype y Trivy, descarga el archivo oficial de sumas y compara el **SHA-256** de lo descargado con el publicado; solo si coinciden instala el binario en `tools/`. Eso garantiza que el archivo no se corrompió ni se alteró por el camino. Lo que no puede garantizar es que la **publicación oficial** sea legítima: en el caso Trivy de 2026 los atacantes reescribieron las etiquetas de versión, y la suma publicada correspondía al binario malicioso, así que habría coincidido. Por eso además se fijan versiones revisadas (no «la última») y lo ideal es verificar la **firma** de la publicación.
11.
12.
