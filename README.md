# Laboratorio de Criptografía Aplicada: Ataques Históricos a SSL/TLS

> **Trabajo Práctico Universitario - Seguridad en Redes y Criptografía**  
> Demostración experimental y matemática de vulnerabilidades en el modo CBC: **BEAST** (2011) y **Lucky 13** (2013).

---

## 📌 Descripción General

Este repositorio contiene dos pruebas de concepto (PoC) académicas, completamente locales y en memoria, desarrolladas en Python para demostrar de forma empírica y matemática los fallos estructurales que llevaron al abandono del modo **CBC (Cipher Block Chaining)** y del paradigma **MAC-then-Encrypt** en las especificaciones modernas de TLS:

1. **BEAST (Browser Exploit Against SSL/TLS):** Demostración de cómo la predictibilidad del Vector de Inicialización (IV) en TLS 1.0 rompe la seguridad IND-CPA, permitiendo la recuperación de secretos byte a byte mediante un ataque de texto plano elegido (*Chosen Plaintext Attack*).
2. **Lucky 13:** Demostración de un oráculo de padding por canal lateral de tiempo (*Timing Side-Channel*), evidenciando cómo discrepancias microscópicas (a nivel microsegundos/nanosegundos) en el cálculo de HMAC-SHA1 revelan la validez del padding.

---

## 🗂️ Estructura del Repositorio

```text
.
├── 01-beast/
│   ├── demo_cbc_predictable_iv.py   # Simulación local y exploit byte a byte por XOR
│   ├── requirements.txt             # Dependencias (cryptography, colorama)
│   ├── .env.example                 # Variables de entorno de referencia
│   └── README.md                    # Documentación teórica del ataque BEAST
│
├── 02-lucky13/
│   ├── demo_lucky13_timing_oracle.py # Medición de alta precisión con time.perf_counter_ns()
│   ├── requirements.txt              # Dependencias (cryptography, colorama, numpy)
│   ├── .env.example                  # Variables de entorno de referencia
│   └── README.md                     # Documentación teórica del ataque Lucky 13
│
├── .gitignore                       # Filtro de entornos virtuales y archivos temporales
└── README.md                        # Este documento
```

---

## 🚀 Inicio Rápido

### Requisitos Previos
* Python 3.10 o superior.

### 1. Laboratorio BEAST (Recuperación de Secreto por IV Predecible)
```bash
cd 01-beast
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 demo_cbc_predictable_iv.py
```

### 2. Laboratorio Lucky 13 (Canal Lateral de Tiempo)
```bash
cd 02-lucky13
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 demo_lucky13_timing_oracle.py
```

---

## 📊 Resumen Comparativo de los Ataques

| Parámetro | BEAST (2011) | Lucky 13 (2013) |
| :--- | :--- | :--- |
| **Protocolo Afectado** | SSL 3.0 / TLS 1.0 (RFC 2246) | TLS 1.1 / TLS 1.2 (RFC 5246) |
| **Causa Raíz** | Reutilización del último bloque cifrado como próximo IV | Verificación asimétrica de padding en *MAC-then-Encrypt* |
| **Tipo de Ataque** | Chosen Plaintext Attack (CPA) algebraico | Timing Side-Channel Padding Oracle |
| **Complejidad** | Lineal: $\mathcal{O}(256 \times N)$ consultas | Estadístico: miles de muestras por byte |
| **Mitigación Temporal** | Record splitting (1/n-1) / IVs aleatorios explícitos (TLS 1.1) | Dummy SHA compression steps (OpenSSL) |
| **Solución Definitiva** | **TLS 1.3 (RFC 8446):** Adopción exclusiva de cifradores autenticados **AEAD** (AES-GCM, ChaCha20-Poly1305) y deprecación total de CBC. |

---

## ⚖️ Descargo de Responsabilidad (Academic Disclaimer)

El código de este repositorio fue desarrollado exclusivamente con fines pedagógicos y de divulgación académica para la asignatura de Seguridad Informática. Ambas demostraciones operan en memoria local y no interactúan con ninguna red ni servidor real.
