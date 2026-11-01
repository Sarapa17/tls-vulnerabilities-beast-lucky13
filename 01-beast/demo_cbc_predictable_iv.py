#!/usr/bin/env python3
"""
===============================================================================
TRABAJO PRÁCTICO: CRIPTOGRAFÍA Y SEGURIDAD EN REDES
DEMOSTRACIÓN DE INSEGURIDAD EN MODO CBC CON VECTOR DE INICIALIZACIÓN PREDECIBLE
Caso de estudio: Fundamento matemático del ataque BEAST (CVE-2011-3389)
===============================================================================

OBJETIVO PEDAGÓGICO:
Demostrar matemáticamente por qué el modo Cipher Block Chaining (CBC) pierde la
propiedad de seguridad IND-CPA (Indistinguibilidad frente a Ataques de Texto Plano
Elegido) cuando el Vector de Inicialización (IV) no es aleatorio e impredecible.

MODELO TEÓRICO:
En el cifrado CBC con cifrador por bloques E_K:
    C_i = E_K( P_i ^ C_{i-1} ), donde C_0 = IV.

Fallo en la especificación de TLS 1.0 (RFC 2246):
    El IV de un nuevo registro TLS se definía como el último bloque de texto cifrado
    del registro inmediatamente anterior:
        IV_nuevo = C_{anterior, ultimo}

Dado que el texto cifrado viaja por el canal y es visible para un observador,
el atacante conoce IV_nuevo ANTES de elegir su texto plano.

DEMOSTRACIÓN MATEMÁTICA DEL ATAQUE:
1. Supongamos un bloque objetivo cifrado:
       C* = E_K( P* ^ IV* )
   donde P* contiene un secreto desconocido y el atacante conoce C* e IV*.

2. El atacante formula una hipótesis de texto plano (Guess = G).

3. Al enviar un nuevo mensaje, el sistema utilizará el IV predecible (IV_sig).

4. El atacante inyecta como texto plano un bloque manipulado con XOR:
       P_elegido = G ^ IV* ^ IV_sig

5. Al cifrar este bloque, el sistema calcula:
       C_elegido = E_K( P_elegido ^ IV_sig )
                 = E_K( (G ^ IV* ^ IV_sig) ^ IV_sig )
                 = E_K( G ^ IV* )

6. Teorema de equivalencia:
       C_elegido == C*  <=>  G == P*

   Si los bloques cifrados coinciden, la hipótesis G es correcta con 100% de certeza,
   ¡sin necesidad de conocer la clave secreta K!

7. Reducción de complejidad:
       Alineando el secreto byte a byte mediante prefijos de longitud variable,
       descifrar un secreto de N bytes requiere a lo sumo N * 256 evaluaciones,
       en contraste con la búsqueda exhaustiva de 256^N combinaciones.
===============================================================================
"""

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from colorama import init, Fore, Style

# Inicializar colores ANSI para visualización didáctica
init(autoreset=True)

BLOCK_SIZE = 16  # AES utiliza bloques de 128 bits (16 bytes)


# =============================================================================
# 1. SIMULACIÓN DE LA CAPA DE REGISTRO VULNERABLE (TLS 1.0)
# =============================================================================
class VulnerableTLSRecordLayer:
    """
    Simula en memoria el comportamiento del cifrado de registros en TLS 1.0.
    Mantiene una clave privada de sesión y reutiliza el último bloque cifrado
    como IV para el registro siguiente (CBC chaining inter-registros).
    """

    def __init__(self, secret_token: bytes):
        # Clave secreta fija de sesión (el atacante NUNCA tiene acceso a ella)
        self._key = os.urandom(BLOCK_SIZE)
        
        # IV inicial aleatorio para la primera conexión
        self._current_iv = os.urandom(BLOCK_SIZE)
        
        # El secreto que el atacante intentará recuperar (ej. cookie de sesión)
        self._secret = secret_token

    def get_predicted_iv(self) -> bytes:
        """
        Retorna el IV que utilizará el próximo registro.
        En TLS 1.0 esto es información pública porque es idéntico al último
        bloque cifrado transmitido en el registro previo.
        """
        return self._current_iv

    def send_authenticated_request(self, user_prefix: bytes) -> tuple[bytes, bytes]:
        """
        Simula una petición emitida por el cliente (por ejemplo, vía un script inyectado).
        El texto plano final se compone de:
            [user_prefix] + [secret_token]
        
        Retorna:
            (iv_usado, ciphertext)
        """
        plaintext = user_prefix + self._secret
        
        # Aplicamos padding PKCS#7 al mensaje
        padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Cifrado en modo CBC usando el IV actual del canal
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._current_iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        iv_used = self._current_iv

        # FALLO CRÍTICO DE TLS 1.0:
        # El próximo IV es el último bloque de este texto cifrado
        self._current_iv = ciphertext[-BLOCK_SIZE:]

        return iv_used, ciphertext

    def send_crafted_probe(self, crafted_block: bytes) -> tuple[bytes, bytes]:
        """
        El atacante inyecta un bloque de prueba arbitrario para verificar su conjetura.
        """
        # Ciframos exactamente 1 bloque de 16 bytes
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._current_iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(crafted_block) + encryptor.finalize()

        iv_used = self._current_iv
        self._current_iv = ciphertext[-BLOCK_SIZE:]

        return iv_used, ciphertext[:BLOCK_SIZE]


# =============================================================================
# 2. OPERACIONES ALGEBRAICAS AUXILIARES
# =============================================================================
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Realiza la operación XOR bit a bit entre dos secuencias de bytes."""
    return bytes(x ^ y for x, y in zip(a, b))


# =============================================================================
# 3. ALGORITMO DE RECUPERACIÓN BYTE A BYTE
# =============================================================================
def execute_cpa_attack(record_layer: VulnerableTLSRecordLayer, secret_length: int) -> bytes:
    """
    Ejecuta el ataque de texto plano elegido (CPA) aprovechando el IV predecible.
    Recupera el secreto completo de longitud `secret_length` byte por byte.
    """
    recovered_secret = bytearray()
    total_probes = 0

    print(f"{Fore.CYAN}==================================================================")
    print(f"{Fore.CYAN}INICIANDO RECUPERACIÓN MEDIANTE ATAQUE DE TEXTO PLANO ELEGIDO")
    print(f"{Fore.CYAN}Objetivo: Recuperar {secret_length} bytes confidenciales sin conocer la clave AES")
    print(f"{Fore.CYAN}==================================================================\n")

    for byte_index in range(secret_length):
        # ---------------------------------------------------------------------
        # PASO A: Alineación de frontera de bloque
        # ---------------------------------------------------------------------
        # Queremos que en el bloque objetivo quede exactamente 1 byte desconocido
        # al final del bloque de 16 bytes.
        #
        # Estructura del bloque objetivo de 16 bytes:
        # [ 15 - (byte_index % 16) bytes de relleno ] + [ bytes ya descubiertos ] + [ 1 byte incógnita ]
        pad_len = (BLOCK_SIZE - 1) - (byte_index % BLOCK_SIZE)
        pad = b"A" * pad_len

        # Emitimos la petición con el prefijo calculado
        iv_target, ciphertext = record_layer.send_authenticated_request(pad)

        # Identificamos qué bloque del texto cifrado contiene nuestro byte incógnita
        target_block_index = byte_index // BLOCK_SIZE
        target_block_start = target_block_index * BLOCK_SIZE
        target_block_end = target_block_start + BLOCK_SIZE
        c_target = ciphertext[target_block_start:target_block_end]

        # En CBC, el "IV efectivo" para un bloque i > 0 es el bloque cifrado C_{i-1}
        if target_block_index == 0:
            iv_effective = iv_target
        else:
            iv_effective = ciphertext[(target_block_index - 1) * BLOCK_SIZE : target_block_start]

        # ---------------------------------------------------------------------
        # PASO B: Búsqueda exhaustiva sobre el espacio del byte (256 valores)
        # ---------------------------------------------------------------------
        # El flujo de texto plano conocido hasta el momento es: pad + recovered_secret.
        # En el bloque objetivo (bloque k), los primeros 15 bytes corresponden a:
        known_stream = pad + bytes(recovered_secret)
        block_k_known = known_stream[target_block_start : target_block_start + 15]

        found_byte = None
        for candidate_val in range(256):
            total_probes += 1

            # Construimos la conjetura de bloque G (exactamente 16 bytes):
            # [ 15 bytes conocidos de ese bloque ] + [ 1 byte candidato ]
            g = block_k_known + bytes([candidate_val])
            assert len(g) == BLOCK_SIZE, "El bloque conjeturado debe medir exactamente 16 bytes"

            # Obtenemos el IV predecible que el sistema usará para nuestra prueba
            iv_next = record_layer.get_predicted_iv()

            # CANCELACIÓN MATEMÁTICA MEDIANTE XOR:
            # P_elegido = G ^ IV_efectivo ^ IV_siguiente
            # Cuando el sistema compute: P_elegido ^ IV_siguiente
            # El término IV_siguiente se cancela: (G ^ IV_efectivo ^ IV_siguiente) ^ IV_siguiente = G ^ IV_efectivo
            crafted_payload = xor_bytes(xor_bytes(g, iv_effective), iv_next)

            # Inyectamos el bloque de prueba
            _, c_probe = record_layer.send_crafted_probe(crafted_payload)

            # Verificación del oráculo: si los cifrados coinciden, la conjetura es correcta
            if c_probe == c_target:
                found_byte = candidate_val
                recovered_secret.append(found_byte)
                break

        if found_byte is None:
            print(f"\n{Fore.RED}[!] Error: No se pudo determinar el byte en la posición {byte_index}")
            sys.exit(1)

        # Salida visual progresiva en consola
        char_repr = chr(found_byte) if 32 <= found_byte <= 126 else f"\\x{found_byte:02x}"
        print(f"[{Fore.GREEN}OK{Style.RESET_ALL}] Byte {byte_index + 1:02d}/{secret_length:02d} "
              f"descifrado: '{Fore.YELLOW}{char_repr}{Style.RESET_ALL}' "
              f"(0x{found_byte:02x}) | Estado actual: {Fore.CYAN}{bytes(recovered_secret).decode(errors='replace')}")

    print(f"\n{Fore.GREEN}==================================================================")
    print(f"{Fore.GREEN}ATAQUE COMPLETADO CON ÉXITO")
    print(f"{Fore.GREEN}Total de pruebas criptográficas enviadas: {total_probes}")
    print(f"{Fore.GREEN}Promedio de pruebas por byte: {total_probes / secret_length:.1f} (Máximo teórico: 256)")
    print(f"{Fore.GREEN}==================================================================")

    return bytes(recovered_secret)


# =============================================================================
# 4. FUNCIÓN PRINCIPAL / REPORTE ACADÉMICO
# =============================================================================
def main():
    print(f"{Fore.MAGENTA}{Style.BRIGHT}")
    print("=" * 70)
    print("  LABORATORIO ACADÉMICO: INSEGURIDAD DE IV PREDECIBLE EN MODO CBC")
    print("  Demostración matemática del principio del ataque BEAST")
    print("=" * 70)
    print(Style.RESET_ALL)

    # Definimos un secreto representativo (ej. una cookie de autenticación de alta entropía)
    secret_real = b"FLAG{CBC_IV_CHAINING_IS_BROKEN}"
    
    print(f"1. Secreto inyectado en el servidor: {Fore.YELLOW}{secret_real.decode()}{Style.RESET_ALL}")
    print(f"2. Algoritmo de cifrado: {Fore.YELLOW}AES-128-CBC{Style.RESET_ALL}")
    print(f"3. Modo de vector de inicialización: {Fore.RED}Encadenado / Predecible (TLS 1.0){Style.RESET_ALL}")
    print(f"4. Longitud del secreto a extraer: {len(secret_real)} bytes\n")

    # Instanciamos el entorno vulnerable en memoria
    oracle = VulnerableTLSRecordLayer(secret_token=secret_real)

    # Ejecutamos la prueba de concepto
    secret_descifrado = execute_cpa_attack(oracle, secret_length=len(secret_real))

    # Verificación final
    print(f"\n{Fore.WHITE}{Style.BRIGHT}RESULTADO DE LA VERIFICACIÓN:")
    print(f"  Texto original : {secret_real}")
    print(f"  Texto obtenido : {secret_descifrado}")

    if secret_real == secret_descifrado:
        print(f"  Estado         : {Fore.GREEN}{Style.BRIGHT}VULNERABILIDAD DEMOSTRADA EXITOSAMENTE (100% coincidencia)\n")
    else:
        print(f"  Estado         : {Fore.RED}FALLO EN LA RECONSTRUCCIÓN\n")

    # Conclusión pedagógica para el informe escrito del alumno
    print(f"{Fore.CYAN}--- NOTA PEDAGÓGICA PARA EL INFORME DEL TP ---")
    print("Por qué este ataque NO funciona en estándares modernos:")
    print("1. TLS 1.1 y 1.2 (RFC 4346 / RFC 5246): Exigen que cada registro CBC lleve un")
    print("   IV explícito, generado de forma aleatoria e impredecible para cada mensaje.")
    print("2. Mitigación 1/n-1 (Record Splitting): Fragmenta el primer byte del mensaje")
    print("   en un registro separado para forzar un nuevo IV aleatorio antes del secreto.")
    print("3. TLS 1.3 (RFC 8446): Eliminó completamente el soporte para el modo CBC,")
    print("   adoptando exclusivamente cifradores autenticados AEAD (ej. AES-GCM, ChaCha20).")
    print("-" * 70)


if __name__ == "__main__":
    main()
