# Demostración Práctica: Ataque BEAST (Browser Exploit Against SSL/TLS)

## 1. Contexto Histórico
Publicado en 2011 por Thai Duong y Juliano Rizzo, el ataque **BEAST** demostró la viabilidad práctica de explotar una debilidad conocida en el modo **CBC (Cipher Block Chaining)** de TLS 1.0 y SSL 3.0.

## 2. La Vulnerabilidad: Encadenamiento de IVs
En el modo CBC estándar, cada bloque de texto plano se opera con XOR contra el bloque de texto cifrado previo antes de pasar por el algoritmo de cifrado por bloques (ej. AES):

$$C_i = E_K(P_i \oplus C_{i-1})$$

Para el primer bloque ($P_1$), se requiere un **Vector de Inicialización (IV)**.

* **El error en TLS 1.0:** El estándar reutilizaba el último bloque cifrado del registro TLS anterior ($C_{last}$) como el IV del nuevo registro entrante:
  $$\text{IV}_{\text{nuevo}} = C_{\text{anterior}}$$
* **Consecuencia:** Como el tráfico en tránsito puede ser interceptado por un atacante en posición Man-in-the-Middle (MitM), **el IV del próximo mensaje es conocido de antemano por el atacante**.

## 3. El Ataque (Chosen Plaintext Attack)
El atacante busca descifrar un secreto (por ejemplo, una cookie de sesión HTTP) inyectando peticiones a través de un canal controlado:

1. **Alineación de Bloque:** El atacante envía datos con una longitud cuidadosamente calculada para que exactamente **1 byte del secreto** quede al final del bloque cifrado objetivo $P$.
2. **Adivinanza (Guessing):** 
   * Supongamos que el atacante quiere probar si el byte desconocido es $g \in [0, 255]$.
   * El atacante conoce el IV del mensaje de la víctima ($IV_v$) y el IV del próximo mensaje que él mismo inyectará ($IV_a$).
   * Confecciona un bloque de prueba $P_{test}$ manipulado con XOR para que coincida matemáticamente con la entrada al cifrador si su adivinanza $g$ es correcta:
     $$P_{test} = P_{guess} \oplus IV_v \oplus IV_a$$
3. **Verificación:** Si el bloque cifrado resultante coincide con el bloque cifrado de la víctima, el byte adivinado es correcto.
4. **Iteración:** Se repite el proceso para los bytes subsiguientes desplazando la ventana de alineación.

## 4. Estructura de Archivos
* `demo_cbc_predictable_iv.py`: Script autocontenido y en memoria que implementa la capa de registros vulnerable y el ataque CPA con cancelación por XOR.
* `requirements.txt`: Dependencias de Python (`cryptography`, `colorama`).
* `.env`: Variables de entorno para pruebas configurables.

## 5. Instrucciones de Ejecución
```bash
cd /Users/tomas/Downloads/Seguridad/01-beast
source venv/bin/activate
python3 demo_cbc_predictable_iv.py
```
