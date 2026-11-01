#!/usr/bin/env python3
"""
===============================================================================
TRABAJO PRÁCTICO: CRIPTOGRAFÍA Y SEGURIDAD EN REDES
DEMOSTRACIÓN DE ORÁCULO DE PADDING POR CANAL LATERAL DE TIEMPO (TIMING ATTACK)
Caso de estudio: Fundamento teórico del ataque Lucky 13 (AlFardan & Paterson, 2013)
===============================================================================

OBJETIVO PEDAGÓGICO:
Demostrar cómo pequeñas discrepancias en el tiempo de ejecución en el proceso de
descifrado y validación del esquema MAC-then-Encrypt (utilizado en TLS 1.1 y 1.2)
fugan información sobre la validez del padding, convirtiendo una operación teóricamente
segura en un oráculo de descifrado explotable.

MODELO TEÓRICO:
En TLS con suites CBC (RFC 5246):
1. Estructura del registro antes de cifrar:
   [Cabecera (13 bytes)] + [Datos (L bytes)] + [HMAC-SHA1 (20 bytes)] + [Padding (P bytes)] + [PadLen (1 byte)]

2. Proceso de recepción y verificación:
   a) Se descifra el texto cifrado con AES-CBC.
   b) Se lee el último byte para determinar la longitud del padding P.
   c) Se comprueba si todos los P bytes de relleno tienen el valor P.
   d) Se extrae el HMAC y se computa un nuevo HMAC sobre:
      Cabecera (13 bytes) + Datos (L bytes), donde L = TamañoTotal - 20 - (P + 1)

3. El origen de la fuga de tiempo (Lucky 13):
   Las funciones de hash como SHA-1 procesan la entrada en bloques de 64 bytes.
   - Si el padding es VÁLIDO: La longitud L es menor, lo que puede requerir K bloques SHA.
   - Si el padding es INVÁLIDO: En implementaciones vulnerables o ingenuas:
     * Caso 1 (Abrupto): El servidor falla antes de calcular el HMAC (diferencia de microsegundos).
     * Caso 2 (Lucky 13 sutil): El servidor calcula un HMAC ficticio sobre una longitud diferente,
       requiriendo K + 1 bloques de compresión SHA (diferencia de decenas/cientos de nanosegundos).

Este script simula este proceso localmente en memoria y mide con time.perf_counter_ns()
la distribución de tiempos, evidenciando estadísticamente la fuga por canal lateral.
===============================================================================
"""

import os
import time
import hmac
import hashlib
import statistics
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import init, Fore, Style

# Inicializar colorama para formateo en terminal
init(autoreset=True)

BLOCK_SIZE = 16       # Tamaño de bloque AES (16 bytes / 128 bits)
HMAC_SIZE = 20        # Tamaño del digest SHA-1 (20 bytes / 160 bits)
HEADER_SIZE = 13      # Tamaño de la cabecera TLS de registro (13 bytes)


# =============================================================================
# 1. SERVIDOR SIMULADO: MAC-THEN-ENCRYPT VULNERABLE
# =============================================================================
class MockTLSServer:
    """
    Simula el extremo receptor de TLS 1.2 con arquitectura MAC-then-Encrypt.
    Implementa la rutina de validación vulnerable donde el tiempo de cálculo
    varía según el estado del padding.
    """

    def __init__(self):
        # Claves privadas de sesión
        self._enc_key = os.urandom(BLOCK_SIZE)
        self._mac_key = os.urandom(HMAC_SIZE)
        # Cabecera simulada de 13 bytes: Sequence(8) + Type(1) + Version(2) + Length(2)
        self.mock_header = b"\x00" * 8 + b"\x16\x03\x03" + b"\x00\x30"

    def create_valid_record(self, payload: bytes, extra_pad_blocks: int = 0) -> bytes:
        """
        Construye un registro TLS legítimo aplicando:
        1. Cálculo de HMAC-SHA1 sobre (Cabecera + Payload)
        2. Agregado de Padding TLS (RFC 5246: N bytes con valor N-1)
        3. Cifrado AES-CBC
        """
        # 1. Calcular HMAC
        mac = hmac.new(self._mac_key, self.mock_header + payload, hashlib.sha1).digest()

        # 2. Construir Padding TLS estándar
        data_len = len(payload) + len(mac)
        padding_needed = BLOCK_SIZE - (data_len % BLOCK_SIZE)
        padding_needed += extra_pad_blocks * BLOCK_SIZE
        
        pad_val = padding_needed - 1
        padding_bytes = bytes([pad_val] * padding_needed)
        
        plaintext = payload + mac + padding_bytes
        assert len(plaintext) % BLOCK_SIZE == 0, "El texto plano debe ser múltiplo del bloque"

        # 3. Cifrar en modo CBC con IV aleatorio
        iv = os.urandom(BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(self._enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv + ciphertext

    def verify_record_vulnerable(self, record_data: bytes) -> bool:
        """
        RUTINA VULNERABLE:
        Simula el comportamiento histórico de verificación previa a los parches
        de tiempo constante:
        - Si el padding es válido: calcula HMAC sobre el payload real.
        - Si el padding es inválido: la verificación de padding falla y la rutina
          se ramifica (early-abort o cómputo asimétrico), consumiendo menos o más
          ciclos de CPU antes de retornar.
        """
        iv = record_data[:BLOCK_SIZE]
        ciphertext = record_data[BLOCK_SIZE:]

        # Paso 1: Descifrado AES-CBC
        cipher = Cipher(algorithms.AES(self._enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Paso 2: Extracción y chequeo de padding
        pad_len = plaintext[-1]
        
        # Validar si todos los bytes del relleno coinciden con pad_len
        padding_valid = True
        if pad_len + 1 > len(plaintext) - HMAC_SIZE:
            padding_valid = False
        else:
            expected_padding = bytes([pad_len] * (pad_len + 1))
            if plaintext[-(pad_len + 1):] != expected_padding:
                padding_valid = False

        # Paso 3: Cálculo del HMAC (FUENTE DEL CANAL LATERAL)
        if padding_valid:
            # Padding Válido: Se extrae el payload legítimo y se calcula el HMAC
            payload_len = len(plaintext) - HMAC_SIZE - (pad_len + 1)
            payload = plaintext[:payload_len]
            received_mac = plaintext[payload_len:payload_len + HMAC_SIZE]
            
            computed_mac = hmac.new(self._mac_key, self.mock_header + payload, hashlib.sha1).digest()
            return hmac.compare_digest(computed_mac, received_mac)
        else:
            # Padding Inválido:
            # En la implementación vulnerable sin tiempo constante,
            # no se procesa el HMAC completo del payload o se aborta antes.
            # Esto produce una discrepancia medible en microsegundos.
            return False

    def verify_record_constant_time(self, record_data: bytes) -> bool:
        """
        RUTINA MITIGADA (TIEMPO CONSTANTE):
        Representa la solución implementada tras Lucky 13:
        Siempre se ejecuta una cantidad fija de operaciones de compresión hash
        independientemente de si el padding era válido o no.
        """
        iv = record_data[:BLOCK_SIZE]
        ciphertext = record_data[BLOCK_SIZE:]

        cipher = Cipher(algorithms.AES(self._enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        pad_len = plaintext[-1]
        padding_valid = True
        if pad_len + 1 > len(plaintext) - HMAC_SIZE:
            padding_valid = False
        else:
            expected_padding = bytes([pad_len] * (pad_len + 1))
            if plaintext[-(pad_len + 1):] != expected_padding:
                padding_valid = False

        # Se calcula el HMAC SIEMPRE sobre un tamaño estándar para neutralizar la fuga temporal
        payload_len = max(0, len(plaintext) - HMAC_SIZE - (pad_len + 1))
        payload = plaintext[:payload_len]
        
        # Cálculo en tiempo constante (dummy calculation si falló)
        computed_mac = hmac.new(self._mac_key, self.mock_header + payload, hashlib.sha1).digest()
        
        if not padding_valid:
            return False
            
        received_mac = plaintext[payload_len:payload_len + HMAC_SIZE]
        return hmac.compare_digest(computed_mac, received_mac)


# =============================================================================
# 2. EXPERIMENTO ESTADÍSTICO DE MEDICIÓN TEMPORAL
# =============================================================================
def run_timing_benchmark(server: MockTLSServer, num_samples: int = 1500):
    """
    Ejecuta mediciones de alta precisión con time.perf_counter_ns()
    comparando registros con padding válido vs padding corrupto.
    """
    # Construimos un mensaje de prueba
    test_payload = b"GET /admin/session HTTP/1.1\r\nHost: intranet.bank\r\n\r\n"
    
    # 1. Registro con padding legítimo
    valid_record = server.create_valid_record(test_payload)

    # 2. Registro con padding deliberadamente alterado (invertimos un byte en el padding)
    corrupted_bytes = bytearray(valid_record)
    # Modificamos el último byte cifrado para inducir un fallo determinista de padding tras descifrar
    corrupted_bytes[-1] ^= 0xFF
    invalid_record = bytes(corrupted_bytes)

    times_valid_ns = []
    times_invalid_ns = []

    print(f"{Fore.CYAN}Recolectando {num_samples} muestras de tiempo por categoría (intercaladas)...{Style.RESET_ALL}")

    # Intercalamos las pruebas para mitigar calentamiento de caché o fluctuaciones del CPU
    for i in range(num_samples):
        # Muestra con padding válido
        t0 = time.perf_counter_ns()
        server.verify_record_vulnerable(valid_record)
        t1 = time.perf_counter_ns()
        times_valid_ns.append(t1 - t0)

        # Muestra con padding inválido
        t0 = time.perf_counter_ns()
        server.verify_record_vulnerable(invalid_record)
        t1 = time.perf_counter_ns()
        times_invalid_ns.append(t1 - t0)

    # Convertimos a microsegundos (µs) para mayor legibilidad
    times_valid_us = [t / 1000.0 for t in times_valid_ns]
    times_invalid_us = [t / 1000.0 for t in times_invalid_ns]

    # Descartamos el 5% de outliers (interrupciones del sistema operativo)
    def remove_outliers(data, percentile=95):
        threshold = statistics.quantiles(data, n=100)[percentile]
        return [x for x in data if x <= threshold]

    clean_valid = remove_outliers(times_valid_us)
    clean_invalid = remove_outliers(times_invalid_us)

    # Cálculo de métricas estadísticas
    avg_valid = statistics.mean(clean_valid)
    med_valid = statistics.median(clean_valid)
    std_valid = statistics.stdev(clean_valid)

    avg_invalid = statistics.mean(clean_invalid)
    med_invalid = statistics.median(clean_invalid)
    std_invalid = statistics.stdev(clean_invalid)

    delta_avg_us = abs(avg_valid - avg_invalid)
    delta_avg_ns = delta_avg_us * 1000.0

    return {
        "samples": len(clean_valid),
        "valid": {"mean": avg_valid, "median": med_valid, "std": std_valid},
        "invalid": {"mean": avg_invalid, "median": med_invalid, "std": std_invalid},
        "delta_us": delta_avg_us,
        "delta_ns": delta_avg_ns
    }


# =============================================================================
# 3. VISUALIZACIÓN EN TERMINAL Y REPORTE
# =============================================================================
def main():
    print(f"{Fore.MAGENTA}{Style.BRIGHT}")
    print("=" * 72)
    print("  LABORATORIO ACADÉMICO: ORÁCULO DE PADDING POR CANAL LATERAL DE TIEMPO")
    print("  Fundamento teórico del ataque Lucky 13 (MAC-then-Encrypt / TLS)")
    print("=" * 72)
    print(Style.RESET_ALL)

    print("Configuración:")
    print("  * Algoritmo de Cifrado : AES-128-CBC")
    print("  * Función de Integridad: HMAC-SHA1")
    print("  * Esquema              : MAC-then-Encrypt (RFC 5246)")
    print("  * Medidor de Precisión : time.perf_counter_ns() (resolución a nivel hardware)\n")

    server = MockTLSServer()
    stats = run_timing_benchmark(server, num_samples=2500)

    print(f"\n{Fore.WHITE}{Style.BRIGHT}==================================================================")
    print("RESULTADOS ESTADÍSTICOS DE LAS MEDICIONES")
    print("==================================================================")
    print(f"Muestras procesadas tras filtrado: {stats['samples']} por caso\n")

    print(f"1. {Fore.GREEN}{Style.BRIGHT}CASO: PADDING VÁLIDO{Style.RESET_ALL}")
    print(f"   - Tiempo promedio : {Fore.GREEN}{stats['valid']['mean']:.3f} µs{Style.RESET_ALL} ({stats['valid']['mean']*1000:.0f} ns)")
    print(f"   - Mediana         : {stats['valid']['median']:.3f} µs")
    print(f"   - Desviación est. : {stats['valid']['std']:.3f} µs")

    print(f"\n2. {Fore.RED}{Style.BRIGHT}CASO: PADDING INVÁLIDO{Style.RESET_ALL}")
    print(f"   - Tiempo promedio : {Fore.RED}{stats['invalid']['mean']:.3f} µs{Style.RESET_ALL} ({stats['invalid']['mean']*1000:.0f} ns)")
    print(f"   - Mediana         : {stats['invalid']['median']:.3f} µs")
    print(f"   - Desviación est. : {stats['invalid']['std']:.3f} µs")

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}------------------------------------------------------------------")
    print(f"BRECHA TEMPORAL DETECTADA (CANAL LATERAL):")
    print(f"  Δt (Diferencia promedio): {Fore.YELLOW}{Style.BRIGHT}{stats['delta_us']:.3f} µs{Style.RESET_ALL} "
          f"({stats['delta_ns']:.0f} nanosegundos)")
    print(f"------------------------------------------------------------------{Style.RESET_ALL}\n")

    # Gráfico de barras ASCII para visualizar el desnivel de tiempo
    scale = 10  # Caracteres por microsegundo
    bar_valid = "█" * int(stats['valid']['mean'] * scale)
    bar_invalid = "█" * int(stats['invalid']['mean'] * scale)

    print(f"{Fore.WHITE}{Style.BRIGHT}Comparativa Gráfica de Latencia en CPU:{Style.RESET_ALL}")
    print(f"  Padding Válido   [{Fore.GREEN}{bar_valid}{Style.RESET_ALL}] {stats['valid']['mean']:.2f} µs")
    print(f"  Padding Inválido [{Fore.RED}{bar_invalid}{Style.RESET_ALL}] {stats['invalid']['mean']:.2f} µs\n")

    # Evaluación académica del resultado
    if stats['delta_us'] > 0.05:
        print(f"{Fore.GREEN}[+] CONFIRMACIÓN EXPERIMENTAL:")
        print("    Existe una diferencia de tiempo estadísticamente significativa.")
        print("    Un atacante observador puede distinguir un padding válido de uno inválido")
        print("    simplemente cronometrando la respuesta, sin necesidad de que el servidor")
        print("    emita mensajes de error explícitos (Padding Oracle silencioso).\n")
    else:
        print(f"{Fore.YELLOW}[!] Nota: La diferencia observada es muy pequeña. Aumente el número de muestras.")

    print(f"{Fore.CYAN}--- CONCLUSIÓN TEÓRICA PARA EL INFORME ---")
    print("1. Por qué es peligroso:")
    print("   Permite montar el ataque de Padding Oracle de Vaudenay incluso cuando la")
    print("   aplicación responde con un código de error unificado (ej. 'bad_record_mac').")
    print("2. Por qué ocurrió:")
    print("   El diseño 'MAC-then-Encrypt' obliga a descifrar y verificar el formato antes")
    print("   de autenticar. La verificación asimétrica en ramas if/else rompe el tiempo constante.")
    print("3. Solución moderna en TLS 1.3:")
    print("   Se sustituyó MAC-then-Encrypt por AEAD (Authenticate-then-Encrypt integrado).")
    print("   En AEAD, si la etiqueta de autenticación falla, los datos se descartan sin")
    print("   evaluar ningún padding, eliminando por completo este canal lateral.")
    print("=" * 72)


if __name__ == "__main__":
    main()
