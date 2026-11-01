# Demostración Práctica: Ataque Lucky 13 (Timing Side-Channel Padding Oracle)

## 1. Contexto Histórico
Publicado en 2013 por Nadhem AlFardan y Kenny Paterson, el ataque **Lucky 13** demostró que incluso después de que los ataques tradicionales de Padding Oracle (como el de Vaudenay en 2002) fueran mitigados con códigos de error uniformes en TLS, la especificación de **MAC-then-Encrypt** continuaba siendo vulnerable a fugas de información a través del tiempo de procesamiento.

El nombre "Lucky 13" proviene del hecho de que se evaluaban 13 bytes de cabecera en el cálculo de MAC de TLS.

## 2. La Vulnerabilidad: Tiempo de Cálculo Asimétrico del HMAC
En las versiones de TLS 1.1 y 1.2 que utilizan suites CBC:
1. El registro recibido se descifra primero.
2. Se extrae y valida el padding (estándar TLS/PKCS#7).
3. Si el padding es válido, se determina la longitud real del payload ($L$) restando el tamaño del padding.
4. Se calcula el HMAC sobre el payload y la cabecera del registro para verificar la integridad.

### El Canal Lateral:
Las funciones de compresión de hash criptográficas (como SHA-1 o SHA-256) procesan los datos en bloques de **64 bytes**:
* Si un padding es válido y largo, la longitud del payload $L$ es menor, lo que puede resultar en **menos bloques de compresión SHA** calculados durante el HMAC.
* Si el padding es inválido, el servidor calcula el HMAC sobre una longitud diferente o ejecuta una rama de validación alternativa.

Esta pequeña diferencia en operaciones de hash introduce una variación en el tiempo de respuesta (desde decenas de nanosegundos hasta microsegundos) que actúa como un **oráculo de padding silencioso**.

## 3. El Ataque y la Demostración
En un entorno de laboratorio:
1. **Modificación de Texto Cifrado:** El script manipula los bytes del penúltimo bloque cifrado para forzar diferentes valores de padding en el último bloque descifrado.
2. **Muestreo Temporal de Alta Resolución:** Se mide el tiempo de ejecución con `time.perf_counter_ns()` para miles de iteraciones.
3. **Análisis Estadístico y Gráfico:** Se calcula la mediana y desviación estándar, generando un gráfico de barras / boxplot comparativo que demuestra visualmente la diferencia de tiempos entre paddings válidos e inválidos.
4. **Comparación con Mitigación:** Se compara la rutina vulnerable contra una implementación mitigada en tiempo constante (*dummy compression* similar a los parches de OpenSSL).

## 4. Estructura de Archivos
* `demo_lucky13_timing_oracle.py`: Simulación local en memoria del oráculo de padding por canal lateral de tiempos.
* `requirements.txt`: Dependencias de Python (`cryptography`, `colorama`, `numpy`).
* `.env`: Parámetros de simulación.

## 5. Instrucciones de Ejecución
```bash
cd /Users/tomas/Downloads/Seguridad/02-lucky13
source venv/bin/activate
python3 demo_lucky13_timing_oracle.py
```
