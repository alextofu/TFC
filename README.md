Detección de Actividad Sospechosa en Sistemas Windows
Aplicación ligera de análisis de seguridad en equipos Windows, diseñada para detectar patrones sospechosos mediante el análisis del visor de eventos. Orientada a usuarios avanzados, técnicos o estudiantes que deseen interpretar la actividad del sistema de forma visual y sencilla.

Funcionalidades principales
Detección de inicios de sesión sospechosos (fallos repetidos o fuerza bruta)

Supervisión de cambios en cuentas de usuario y grupos

Registro de errores críticos en aplicaciones

Identificación de conexiones remotas externas

Análisis de eventos del firewall

Correlación de eventos y generación de resúmenes

Módulo opcional de IA para clasificación de riesgo

Tecnologías utilizadas
Python 3.12

FastAPI

win32evtlog

scikit-learn

HTML5 y JavaScript

Instalación y uso
Clona el repositorio y accede al backend:
git clone https://github.com/tu-usuario/proyecto-tfc.git
cd backend

Instala las dependencias:
pip install -r requirements.txt

Ejecuta la API:
python -m uvicorn app:app --reload

Abre el archivo TRABAJO_FINAL_BASE.html desde el navegador.

Información adicional
Este proyecto se ha desarrollado como Trabajo Final de Ciclo del CFGS de Administración de Sistemas Informáticos en Red (ASIR), con un enfoque práctico y educativo sobre supervisión y seguridad en sistemas Windows.
