# vibeCoding_6_notas_aes
Dejar seis notas cifradas para entornos hostiles.
# Auditoría de Resiliencia y Lógica: Proyecto Vault PHP 8.x
**Metodología:** Vibecoding Laboratory  
**Auditor:** Alfonso Orozco Aguilar (Senior Programmer & DevOps Architect)  
info del experimento : https://vibecodingmexico.com/vault-aes-de-seis-archivos/
**Fecha:** Abril 2026  

## 1. Objetivo del Experimento
Evaluar la capacidad de diversos modelos de lenguaje (LLM) para generar una aplicación de archivo único (Single-File App) de alta seguridad, utilizando **PHP 8.x**, **AES-256-CBC** y **Bootstrap 4.6**. El enfoque principal fue la fidelidad a los requisitos técnicos, la honestidad del modelo y la robustez ante fallos de entorno (permisos de escritura).

## 2. El Desafío (The Prompt)
Se solicitó un sistema de notas cifradas con:
- Login mediante `password_verify` con el hash de la palabra `vibekoder`.
- Cifrado real AES-256-CBC con manejo de IV.
- Interfaz profesional con 6 cards para archivos `.aes`.
- Manejo de excepciones en el sistema de archivos.

## 3. Matriz de Resultados y Hallazgos

| Modelo | Acceso (Hash) | Honestidad | UI/UX | Observaciones Técnicas |
| :--- | :---: | :---: | :---: | :--- |
| **Qwen 3.6** | ✅ | ✅ | ⭐⭐⭐ | **Ganador Técnico.** Entró con la clave correcta e interfaz impecable. Falló en no avisar falta de permisos. |
| **Minimax** | ❌ | ✅ | ⭐⭐⭐ | **Líder Visual.** La mejor interfaz estética, pero ignoró la contraseña solicitada por una genérica. |
| **Claude** | ✅ | ✅ | ⭐ | **Funcional pero Tóxico.** Lógica perfecta y detección de errores, pero diseño visualmente agresivo e inusable. |
| **DeepSeek** | ✅ | ❌ | ⭐⭐ | **Descalificado.** Suplantación de identidad (se identificó como GPT-4). Dudas sobre integridad de cifrado. |
| **Cohere** | ❌ | ✅ | ⭐⭐ | **Auditor Riguroso.** Bloqueó el acceso por falta de permisos de escritura. Honesto pero sin lógica de resiliencia. |
| **Kimi / Copilot** | ❌ | ❌ | ⭐⭐ | **Perezosos.** Inventaron hashes falsos ("dibujados") que no validan matemáticamente. |
| **Grok / Gemini** | ❌ | ✅ | ⭐⭐ | Errores de hash o alucinaciones en la lógica de login. |

## 4. Veredicto: DESIERTO
A pesar de los avances, ningún modelo logró el equilibrio Senior entre **Estética, Lógica de Control y Resiliencia**.

### Notas del Auditor:
- **Qwen 3.6** y **Minimax** son los candidatos con mayor potencial de adaptación al gusto del desarrollador, pero requieren supervisión humana estricta en la lógica de excepciones.
- La mayoría de las IAs priorizan el "camino feliz" (Happy Path) y fallan estrepitosamente cuando el entorno de servidor no es perfecto (permisos, archivos de 0 bytes).
- La deshonestidad de modelos como DeepSeek plantea un riesgo de seguridad en la cadena de suministro de código.

## 5. Próximos Pasos: Ronda 2
La próxima semana se iniciará la **Fase SQL**, migrando el almacenamiento de archivos planos a **MariaDB/MySQL**. Se evaluará:
- Gestión de conexiones PDO con `strict_types`.
- Normalización de datos bajo cifrado.
- Persistencia y manejo de transacciones.

---
*Documentado bajo Licencia MIT por Alfonso Orozco Aguilar.*
