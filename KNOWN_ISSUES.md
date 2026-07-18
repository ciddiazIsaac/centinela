# Known Issues & Maintenance Notes

## `err.request.res` — Internal axios API (httpClient.ts)

**Archivo afectado:** [`src/utils/httpClient.ts`](./src/utils/httpClient.ts) — bloque `catch` del handler de `maxContentLength`.

### Contexto

Cuando axios aborta una respuesta a mitad de stream por exceder `maxContentLength`, construye el `AxiosError` **antes** de que el objeto `response` esté completamente hidratado. Como resultado, `err.response` está vacío o es `undefined` en ese punto.

La fuente real de los headers y el status code en ese escenario es `err.request.res` — el objeto `IncomingMessage` nativo de Node.js que queda expuesto a través del adaptador HTTP interno de axios.

### El riesgo

`err.request.res` **no es parte de la API pública documentada de axios**. Funciona hoy porque es un detalle de implementación del adaptador HTTP interno, pero podría desaparecer o cambiar en una versión mayor futura sin que eso constituya un breaking change desde el punto de vista de semver (porque axios nunca prometió esa forma públicamente).

### Cómo mitigarlo al actualizar axios

> ⚠️ **Si actualizas axios a una versión mayor, corre `maxContentLength.test.ts` primero.**

```bash
npx vitest run __tests__/maxContentLength.test.ts
```

Ese test levanta un servidor local que envía más de 50 KB de datos y valida que el finding `response-truncated` se genere correctamente. Si `err.request.res` deja de funcionar en una versión futura, ese test fallará antes de que el cambio llegue a producción, dándote la señal de que hay que ajustar el fallback en `httpClient.ts`.

### Alternativas a explorar si el test falla tras un upgrade

1. Interceptar la respuesta con un `transformResponse` o un interceptor de axios antes de que el error sea lanzado.
2. Implementar el límite de tamaño manualmente con un `stream` de Node.js, reemplazando la dependencia en `maxContentLength` de axios por completo.
3. Revisar si la versión nueva de axios expone los headers por otra ruta en el objeto de error.
