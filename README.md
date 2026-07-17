# 🛡️ Centinela

**Centinela** es un escáner de seguridad HTTP rápido y extensible. Audita aplicaciones web y detecta vulnerabilidades en encabezados de seguridad, configuraciones CORS, atributos de cookies, y rutas sensibles expuestas.

## Características

- 🔒 **Security Headers**: Valida CSP, HSTS, X-Frame-Options, y más.
- 🍪 **Cookies**: Verifica flags `Secure`, `HttpOnly`, y `SameSite`.
- 🌐 **CORS**: Detecta configuraciones excesivamente permisivas (e.g., wildcard origin con credenciales).
- 📁 **Rutas Expuestas**: Busca archivos sensibles como `/.git/config`, `/.env`, o `/admin`.
- 🛡️ **SSRF Protection**: Las peticiones incluyen validación DNS para prevenir que la herramienta ataque redes internas (SSRF / DNS rebinding).
- 📄 **Reportes**: Genera resultados en JSON estructurado o reportes detallados en PDF.
- 💻 **Interfaces**: Úsalo vía CLI o mediante su API REST (Express).

## Requisitos

- Node.js >= 18

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/ciddiazIsaac/centinela.git
   cd centinela
   ```

2. Instala dependencias:
   ```bash
   npm install
   ```

3. Copia el entorno:
   ```bash
   cp .env.example .env
   ```

## Uso de la CLI

Escanea una URL y ve el resultado con formato colorido en la terminal:

```bash
npm run cli -- scan https://example.com
```

**Guardar el reporte como PDF**:
```bash
npm run cli -- scan https://example.com --output reporte.pdf
```

**Obtener salida en crudo (JSON)**:
```bash
npm run cli -- scan https://example.com --json
```

## Uso de la API

Inicia el servidor (por defecto en el puerto 3001):
```bash
npm run dev
```

### 1. Iniciar un escaneo
```bash
curl -X POST http://localhost:3001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### 2. Descargar reporte PDF
Usando el `id` devuelto en el paso anterior:
```bash
curl -OJ http://localhost:3001/api/scan/:id/report.pdf
```

## Pruebas

Corre la suite de pruebas (unitarias y de integración):
```bash
npm test
```

Para ver la cobertura:
```bash
npm run test:coverage
```
