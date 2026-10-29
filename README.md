# Lexy Hub · Sistema de licencias (backend + panel web)

Contenido del paquete:

```
LexyHub_Licencias_Web/
├── README.md                  Este archivo: instalación y despliegue
├── requirements.txt           Dependencias de Python
├── .env.example               Variables de entorno de ejemplo (copiar a .env)
├── backend/
│   ├── main.py                API Flask (admin, cliente, auditoría, sesiones)
│   └── schema.sql             Esquema SQLite (se aplica automáticamente al arrancar)
├── web/
│   ├── index.html             Panel web (login, cambio de contraseña, dashboard, generador, licencias, historial)
│   ├── app.js                 Lógica del panel (sin credenciales)
│   └── styles.css             Estilos oscuros (negro / gris / azul), responsive
├── tests/
│   └── test_system.py         15 pruebas automáticas (cubren los 17 escenarios obligatorios) contra la app real y SQLite
└── docs/
    ├── GUIA_ADMIN.md          Generar, activar, revocar, restablecer HWID, desvincular cuentas
    ├── LIMITACIONES.md        Limitaciones reales del entorno y del diseño
    └── TEST_RESULTS.txt       Salida real de la última ejecución de pruebas
```

El script de Roblox modificado (`LexyHub.txt`) se entrega aparte.

## 1. Requisitos

- Python 3.10 o superior.
- `pip install -r requirements.txt`
  - `argon2-cffi` es recomendado (Argon2id). Si no está instalado, el backend usa scrypt, que es un KDF seguro pero menos recomendado.

## 2. Instalación local (desarrollo)

```bash
pip install -r requirements.txt
cd backend
python main.py                       # http://127.0.0.1:8000
```

En desarrollo, si no defines `LEXY_SECRET_KEY` y `LEXY_KEY_PEPPER`, el servidor genera secretos aleatorios y los guarda en `data/lexyhub.devsecrets.json` (permisos 600). Así las keys siguen siendo válidas tras reiniciar. **No uses ese modo en producción.**

En el primer acceso a `http://127.0.0.1:8000`:
1. Usuario `admin`, contraseña `admin` (solo para la configuración inicial).
2. El panel te obliga a establecer una contraseña nueva (mínimo 12 caracteres, mayúsculas, minúsculas, números y símbolo).
3. Hasta completar ese cambio, todas las rutas administrativas devuelven `403 password_change_required`.

## 3. Despliegue en producción

### 3.1. Requisitos del servidor

- Un servidor o plataforma con **HTTPS** (Render, Railway, un VPS con Nginx/Caddy + Let's Encrypt, etc.). El backend no debe servirse por HTTP plano en internet.
- Un disco persistente para la base de datos SQLite (por ejemplo `/var/lib/lexyhub/`). Si la plataforma borra el disco en cada despliegue, las licencias se pierden: usa un volumen persistente.

### 3.2. Variables de entorno obligatorias

Copia `.env.example` a `.env` en el servidor y rellena:

| Variable | Descripción |
|---|---|
| `LEXY_ENV=production` | Activa cookies `Secure`, HSTS y las comprobaciones de arranque. |
| `LEXY_SECRET_KEY` | Secreto de la aplicación, al menos 32 caracteres. |
| `LEXY_KEY_PEPPER` | Pepper para el HMAC de las keys, al menos 32 caracteres. **Si lo cambias, todas las keys existentes dejan de reconocerse.** Guárdalo con copia de seguridad. |
| `LEXY_BOOTSTRAP_PASSWORD` | Contraseña temporal del primer acceso. Debe tener al menos 12 caracteres y **no puede ser `admin`**: en producción el servidor no arranca con la contraseña por defecto. |
| `LEXY_DB_PATH` | Ruta absoluta del archivo SQLite en el disco persistente. |
| `LEXY_TRUST_PROXY=1` | Si hay un proxy HTTPS delante (necesario para cookies seguras y límites por IP correctos). |
| `LEXY_ROBLOX_VERIFY=profile` | Obligatorio en producción (verificación de cuenta, ver `docs/LIMITACIONES.md`). |

Generar secretos:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Cargar el entorno y arrancar con un solo worker (ver nota de concurrencia):

```bash
set -a; source .env; set +a
cd backend
gunicorn -w 1 --threads 8 -b 127.0.0.1:8000 "main:create_app()"
```

Un único worker es intencionado: el limitador de peticiones y el cierre de transacciones de activación viven en el proceso. Con SQLite, varios procesos escribiendo a la vez no es una configuración recomendable.

### 3.3. Proxy HTTPS (ejemplo Caddy)

```
licencias.tudominio.com {
    reverse_proxy 127.0.0.1:8000
}
```

Caddy obtiene el certificado automáticamente. Con Nginx, usa Certbot y `proxy_pass http://127.0.0.1:8000;` añadiendo `X-Forwarded-For`, `X-Forwarded-Proto` y `X-Forwarded-Host`.

### 3.4. Servicio systemd (ejemplo)

```ini
[Unit]
Description=Lexy Hub license backend
After=network.target

[Service]
WorkingDirectory=/opt/lexyhub/backend
EnvironmentFile=/opt/lexyhub/.env
ExecStart=/opt/lexyhub/.venv/bin/gunicorn -w 1 --threads 8 -b 127.0.0.1:8000 "main:create_app()"
Restart=always
User=lexyhub

[Install]
WantedBy=multi-user.target
```

### 3.5. La URL real del backend

Este paquete no incluye ninguna URL de servidor en funcionamiento: no puedo desplegar un servicio desde aquí. Cuando tengas el backend publicado en tu dominio (por ejemplo `https://licencias.tudominio.com`), esa es la URL que va en el script, en la variable `License.url`:

```lua
local License = { url = "https://licencias.tudominio.com", ... }
```

Mientras siga en `TU-BACKEND-URL`, la pestaña Key muestra **ERROR DE CONEXIÓN** y ninguna función de auto-join o auto-steal se activa.

## 4. Pruebas

```bash
python -m unittest discover -s tests -v
```

Las pruebas ejecutan la aplicación real con una base de datos SQLite real. La única parte simulada es la consulta HTTP al perfil público de Roblox, porque el entorno donde se generó este paquete no tiene salida a internet. La salida de la última ejecución está en `docs/TEST_RESULTS.txt`.

## 5. Seguridad implementada (resumen)

- Contraseñas con Argon2id (o scrypt como respaldo), nunca en texto plano.
- Keys con HMAC-SHA256 y pepper; solo se guarda el hash. La key completa se muestra una vez al generarla.
- Sesiones en cookie `HttpOnly`, `SameSite=Strict`, `Secure` en producción, con caducidad absoluta y por inactividad. Al cambiar la contraseña se revocan todas las sesiones.
- Token CSRF en todas las peticiones administrativas que modifican datos, y comprobación de `Origin`.
- Permisos comprobados en el servidor en cada ruta `/api/admin/*`; el cliente nunca puede pedir operaciones administrativas.
- Límite de intentos de login por IP y por usuario, con bloqueo temporal.
- Límites de frecuencia en rutas de cliente y administrativas.
- Consultas SQL parametrizadas; validación de tipos y rangos en cada entrada.
- Cabeceras: CSP estricta (sin scripts ni estilos inline), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, HSTS en producción.
- Auditoría sin contraseñas, tokens de sesión ni keys completas.
- Transacciones `BEGIN IMMEDIATE` en generación y activación; restricciones `UNIQUE` y `CHECK` en la base de datos.

Consulta `docs/GUIA_ADMIN.md` para el uso diario y `docs/LIMITACIONES.md` antes de vender licencias.
