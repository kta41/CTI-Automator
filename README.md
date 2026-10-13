<div align="center">

# ⚡ CTI-Automator: Operational Threat Intelligence

### Pipeline Privado de Ingesta OSINT y Automatización hacia OpenCTI

[![Status](https://img.shields.io/badge/Status-Development-success?style=for-the-badge&logo=statuspage&logoColor=white)](https://github.com/kta41/CTI-Automator)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-Integration-003B5C?style=for-the-badge&logo=graphql&logoColor=white)](https://www.opencti.io/)
[![AI](https://img.shields.io/badge/Local_AI-Ollama-white?style=for-the-badge&logo=ollama&logoColor=black)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-gray?style=for-the-badge)](LICENSE)

<br/>

### 🛠️ Stack Tecnológico
**Lenguaje & Empaquetado:** Python 3.11+ | pyproject.toml  
**Ingesta & Modelado:** Requests | pdfplumber | Pydantic  
**Motor IA & Orquestación:** Ollama (`qwen`) | FastMCP  
**Exportación CTI:** pycti (OpenCTI) | PyMISP | STIX 2.1  
**CI/CD & Calidad:** Ruff | Mypy | Pytest | GitHub Actions  

<br/>

<p align="center">
  Un <b>agente de Inteligencia de Amenazas (CTI)</b> modular y <i>privacy-first</i>.<br/>
  Diseñado para ingerir OSINT crudo, extraer Indicadores de Compromiso (IoCs) accionables y mapear TTPs directamente hacia <b>OpenCTI</b> usando lógica determinista e IA local.
</p>

</div>

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=50&section=header" width="100%" />

---

## 🏗️ Arquitectura del Sistema

CTI-Automator opera a través de un pipeline secuencial de "Tubería" (Collector -> Parser -> Emitter) para garantizar la integridad de los datos antes de su inyección en las plataformas de defensa.

```text
                                  [ Fuentes de Inteligencia ]
                             (AlienVault OTX, Abuse.ch, Informes PDF)
                                               │
                                               ▼
                                  ┌────────────────────────┐
                                  │  Módulo Collector (In) │
                                  │ APIs REST & pdfplumber │
                                  └────────────┬───────────┘
                                               │
                   ┌───────────────────────────┴───────────────────────────┐
                   ▼                                                       ▼
     ┌───────────────────────────┐                           ┌───────────────────────────┐
     │ Extracción Determinista   │                           │ Extracción Semántica (IA) │
     │ Regex para IoCs (IP, URL) │                           │ Ollama (Qwen) via FastMCP │
     │ Limpieza y Defanging      │                           │ Mapeo MITRE ATT&CK        │
     └─────────────┬─────────────┘                           └─────────────┬─────────────┘
                   │                                                       │
                   ├────────────────► [ Pydantic Models ] ◄────────────────┤
                   │                (Estructura Unificada)                 │
                   ▼                                                       ▼
     ┌───────────────────────────┐                           ┌───────────────────────────┐
     │   Exportador a OpenCTI    │                           │    Exportador STIX 2.1    │
     │ Cliente pycti / GraphQL   │                           │ Generación de JSON local  │
     └───────────────────────────┘                           └───────────────────────────┘
```

El agente desacopla la obtención de los datos de su procesamiento, permitiendo conectar múltiples fuentes o destinos sin alterar el motor central.

---

## 📁 Estructura del Repositorio

```text
.
├── src/cti_automator/   # Código fuente principal
│   ├── cli.py           # Entrypoint para la terminal
│   ├── connectors/      # Clientes API (OTX, ThreatFox)
│   ├── parsers/         # Expresiones regulares e IA (Defanging)
│   └── emitters/        # Clientes de OpenCTI y exportadores STIX
├── tests/               # Pruebas unitarias (Pytest)
├── docs/                # Documentación de la arquitectura
├── .github/workflows/   # CI/CD: Pipeline de release automatizada
├── pyproject.toml       # Configuración y dependencias del paquete
└── .env.example         # Plantilla de tokens y configuración
```

Este repositorio está preparado para distribución. El pipeline de GitHub Actions compilará y generará automáticamente un *Release* (`.whl` y `.tar.gz`) cada vez que se publique un *tag* semántico.

---

## ⚙️ Configuración y Desarrollo

Construido con tipado estricto y herramientas modernas de DevSecOps, el entorno local se despliega así:

```bash
# Aislar e instalar con herramientas de desarrollo
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Aplica los controles de calidad (el código sucio genera inteligencia poco fiable):

```bash
ruff check src tests  # Linting & Formateo
mypy src              # Comprobación estricta de tipos
pytest                # Batería de tests
```

---

## 📡 Conectores Operativos (Fase 2)

La capa de ingesta determinista es estricta y modular. Actualmente expone dos clientes principales para la recopilación continua de OSINT:

- `cti_automator.connectors.OTXClient`: Extrae los pulsos a los que estás suscrito en AlienVault OTX.
- `cti_automator.connectors.ThreatFoxClient`: Consulta Abuse.ch ThreatFox en busca de infraestructura activa de malware.

**Bajo el capó:**
Ambos conectores imponen la integridad de los datos mediante modelos **Pydantic**. Los fallos de red o las respuestas malformadas de las APIs upstream se capturan y normalizan en un `ConnectorError` estándar. 

*Nota: Las credenciales deben inyectarse a través de variables de entorno (ver `.env.example`). Para mantener los estándares de seguridad de contenedores, el paquete no carga archivos `.env` automáticamente de forma interna.*

---

## 💡 Ejecución y Uso

<details>
<summary><b>1. Ejecución desde CLI</b></summary>

Una vez instalado, la herramienta se registra globalmente y puede ejecutarse desde la terminal:

```bash
# Ingesta desde una API y exportación a JSON STIX
cti-automator ingest --source otx --export stix

# Parseo de un informe PDF utilizando el agente IA
cti-automator parse --file report.pdf --model qwen --export opencti
```
</details>

<details>
<summary><b>2. Configuración de Credenciales</b></summary>

Copia la plantilla de entorno e introduce tus tokens de OpenCTI y fuentes:

```bash
cp .env.example .env
nano .env
```
Asegúrate de exportar las variables antes de ejecutar la herramienta: `set -a; source .env; set +a`.
</details>

---

<div align="center">

Desarrollado y mantenido por **[Tomás Vinuesa Lago](https://github.com/Kta41)**  
*Las contribuciones, sugerencias y comentarios siempre son bienvenidos.*

</div>