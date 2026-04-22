# vibeCoding_6_notas_aes
Dejar seis notas cifradas para entornos hostiles.
# Auditoría de Resiliencia y Lógica: Proyecto Vault PHP 8.x
**Metodología:** Vibecoding Laboratory  
**Auditor:** Alfonso Orozco Aguilar (Senior Programmer & DevOps Architect)  
**Fecha:** Abril 2026

**info del experimento:** https://vibecodingmexico.com/vault-aes-de-seis-archivos/


## 1. Objetivo del Experimento
Evaluar la capacidad de diversos modelos de lenguaje (LLM) para generar una aplicación de archivo único (Single-File App) de alta seguridad, utilizando **PHP 8.x**, **AES-256-CBC** y **Bootstrap 4.6**. El enfoque principal fue la fidelidad a los requisitos técnicos, la honestidad del modelo y la robustez ante fallos de entorno (permisos de escritura).

Nota:
As of April 16, 2026, GitHub is experiencing several service disruptions and reported issues, primarily affecting Copilot, Codespaces, and specific API integrations. 

No se pudo hacer mucho de otras cosas  por problemas de Github. Por eso por lascosasserias uso GITEA.

## 2. El Desafío (The Prompt)
Se solicitó un sistema de notas cifradas con:
- Login mediante `password_verify` con el hash de la palabra `vibekoder`.
- Cifrado real AES-256-CBC con manejo de IV.
- Interfaz profesional con 6 cards para archivos `.aes`.
- Manejo de excepciones en el sistema de archivos.

Prompt Sugerido para la IA
Rol: Actúa como un Senior Full-Stack Developer experto en PHP y Seguridad.

Objetivo: Crear una Single-File Web App (un solo archivo PHP) que funcione como un “Vault” de notas de texto cifradas.

## Requisitos Técnicos:

Frontend: Php 8.x Bootstrap 4.6.x (CDN), Font Awesome 5.15.4, y jQuery (para los modales).

Seguridad: Uso de la extensión openssl de PHP para cifrado AES-256-CBC.

## Funcionalidad y Flujo:

Login Inicial: Pantalla de inicio centrada que pida usuario admin y contraseña. El acceso se permite si el hash de la contraseña coincide con el de la palabra “vibekoder”.

Para el login, usa password_verify contra un hash pre-generado de ‘vibekoder’ para evitar guardar la palabra en texto plano dentro del código. Para el AES, asegúrate de concatenar el IV al inicio del archivo guardado para poder recuperarlo al descifrar.“

## Interfaz Principal:

Navbar fija con 3 opciones de menú, un enlace externo y un botón de “Salir” (cerrar sesión). Tambien un footer, ambos fijos.

Un Jumbotron de bienvenida.

Identificarte como modelo en la barra superior de navegacion, y poner ip y version de php en el footer.
Grid de 6 tarjetas (Cards) que representen los archivos nota1.aes hasta nota6.aes.

Gestión de Archivos:

Al cargar, debe verificar si los archivos existen y si el directorio tiene permisos de escritura. Si no existen, crearlos vacíos (máx 4096 bytes).

Cada nota se muestra inicialmente como texto cifrado (o un placeholder).

Acciones por Nota:

Botón “Leer/Editar”: Abre un Modal que pide una “Clave de Cifrado” (diferente a la de login). Al ingresarla, descifra el contenido del archivo .aes correspondiente y lo muestra en un textarea.

Botón “Grabar”: Cifra el contenido del textarea con la clave proporcionada y lo guarda en el disco.

Botón “Copiar”: Botón rápido para copiar el texto descifrado al portapapeles.

## Restricciones de Código:

Todo debe estar contenido en un único archivo PHP 8.x.

Manejar el cifrado con una función que incluya un IV (Initialization Vector) para seguridad real.

Diseño limpio y profesional (Vibecoding style).

FIN DE PROMPT
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
