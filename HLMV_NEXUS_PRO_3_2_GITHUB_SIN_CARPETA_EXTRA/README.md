# HLMV NEXUS PRO 3.2 — Minimal · GitHub · Usuarios y permisos

Sistema de Bienes Nacionales del Hospital Leonardo Martínez Valenzuela. **Código fuente, base de datos vacía**. No contiene bienes, contraseñas ni información institucional.

## Novedad: tres perfiles con cuentas individuales

- **Administrador**: crea cuentas, gestiona perfiles, altas/ediciones/importaciones, eliminaciones, backups y restauración de inventarios.
- **Inspector de Bienes**: crea/edita bienes, empleados, áreas, asignaciones, importaciones Excel/PDF y marca revisiones. **No** administra cuentas, elimina bienes ni descarga respaldos completos.
- **Consulta**: busca bienes, ve áreas/responsables, abre fichas QR y exporta reportes Excel/Word. **No** modifica ni importa registros.

Los permisos se comprueban en el servidor. Las contraseñas se almacenan mediante hash PBKDF2 y sal aleatoria; el administrador no puede leerlas, pero puede restablecerlas. Si se desactiva un usuario o cambia su perfil/contraseña, sus sesiones anteriores se invalidan. No puede desactivarse el último administrador.

## Primera instalación en Windows

1. Instala **Python 3.10+**. Para PDF SIAFI, ejecuta `python -m pip install -r requirements-pdf.txt`.
2. Extrae el ZIP en una carpeta exclusiva. Copia `.env.ejemplo` a `.env` dejando `HLMV_CLOUD_MODE=0` y `HLMV_PUBLIC_URL=` vacío.
3. Haz doble clic en `INICIAR_SERVIDOR_WINDOWS.bat`. Entra a `http://127.0.0.1:8895/index.html`.
4. Crea el primer **administrador**, con nombre, usuario y contraseña de mínimo 12 caracteres. Solo se permite desde la propia PC, en modo privado y **antes de activar cualquier túnel**.
5. Entra en **Usuarios y permisos** y crea cuentas **Inspector de bienes** o **Consulta**. Cada persona usa su propio usuario y contraseña.
6. Los registros se crean vacíos en `datos/`; se excluyen de GitHub. Haz respaldos externos antes de añadir datos oficiales.

### Si ya tienes una base de versiones 3.0/3.1

Realiza una copia de seguridad y conserva tu carpeta `datos/` **fuera del repositorio**. Copia el código nuevo, conserva `datos/` y crea la primera cuenta de administrador en modo local privado. Los PIN compartidos antiguos no sirven para iniciar sesión en 3.2. Evita abrir el túnel hasta crear el administrador y los usuarios correspondientes.

## Subir a GitHub

1. Crea un repositorio **privado**.
2. Sube el contenido de esta carpeta, con `index.html` en la raíz. La carpeta `datos/`, `.env`, PDFs, Excel y ZIP quedan excluidos por `.gitignore`.
3. GitHub Pages **no ejecuta** Python ni SQLite. La interfaz y los QR protegidos necesitan el servidor central funcionando.

## Publicación HTTPS con un dominio fijo y Cloudflare Tunnel

1. En una computadora/servidor con un volumen persistente, configura el acceso administrativo **antes de abrir el túnel**. Si la base es nueva y el primer inicio será directamente en modo público, define estas variables como secretos del servidor:
   - `HLMV_CLOUD_MODE=1`
   - `HLMV_PUBLIC_URL=https://inventario.tudominio.com` (sustituye por tu dominio real y estable)
   - `HLMV_ADMIN_USER=administrador`
   - `HLMV_ADMIN_PASSWORD=<contraseña aleatoria de 12-128 caracteres>`
2. Cuando ya exista una cuenta administradora en la base, las credenciales de la primera creación dejan de ser necesarias como variables de entorno. **No** publiques `.env` en GitHub.
3. Protege el dominio en **Cloudflare Access** con correos institucionales autorizados, antes de publicar cualquier información real.
4. Crea el túnel permanente a `http://127.0.0.1:8895` en la PC, sin abrir puertos del router. Para Docker, monta un volumen persistente en `/data`.
5. Comprueba tres cuentas reales de prueba y que un QR dirige a `https://inventario.tudominio.com/index.html#/bien/NUMERO_SIAFI`. Solo después imprime etiquetas permanentes.

> **Confidencialidad:** un repositorio privado protege el código de una publicación accidental, pero la información institucional se mantiene exclusivamente en la base de datos local del servidor. Antes de usar datos reales en internet, Informática debe validar accesos, respaldo externo, sistema operativo, firewall y retención de datos.

## Archivos principales

- `index.html` — sitio principal y control visual de perfiles.
- `app/server.py` — rutas protegidas, inventario, PDF/Excel, QR, reportes.
- `app/central_auth.py` — usuarios, contraseñas, sesiones, roles.
- `app/pro.js`, `app/*.css` — diseño minimalista y funciones.
- `vendor/` — generación de códigos QR.
- `INICIAR_SERVIDOR_WINDOWS.bat` — iniciar localmente desde Windows.
- `Dockerfile` — despliegue opcional con servidor y volumen.

Pruebas de sintaxis: `python -m compileall -q app herramientas`. La publicación y la seguridad requieren validación en la infraestructura real.
