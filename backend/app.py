import win32evtlog
import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np
from collections import defaultdict, Counter
import os
import ipaddress

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model_patron = joblib.load("threat_pattern_model.pkl") if os.path.exists("threat_pattern_model.pkl") else None

@app.get("/analizar_actividad")
def analizar_actividad():
    server = 'localhost'
    log_type = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    event_ids = [4625, 4624]

    eventos_por_usuario = defaultdict(list)
    ahora = datetime.datetime.now()

    handle = win32evtlog.OpenEventLog(server, log_type)
    try:
        while True:
            registros = win32evtlog.ReadEventLog(handle, flags, 0)
            if not registros:
                break
            for evento in registros:
                if evento.EventID in event_ids:
                    fecha = evento.TimeGenerated
                    if (ahora - fecha).total_seconds() > 600:
                        continue
                    detalles = evento.StringInserts
                    if detalles and len(detalles) >= 6:
                        usuario = detalles[5]
                        eventos_por_usuario[usuario].append((fecha, evento.EventID))
    finally:
        win32evtlog.CloseEventLog(handle)

    for usuario, eventos in eventos_por_usuario.items():
        eventos.sort()
        ids = [e[1] for e in eventos]
        if ids.count(4625) >= 3 and 4624 in ids:
            return {"status": "sospechoso", "aviso": f"⚠️ El usuario {usuario} falló varias veces y luego accedió con éxito."}
        elif ids.count(4625) >= 3:
            return {"status": "advertencia", "aviso": f"🚨 Múltiples intentos fallidos de inicio de sesión detectados para el usuario {usuario}."}

    return {"status": "seguro", "aviso": "✅ Actividad de inicio de sesión normal en los últimos 10 minutos."}

@app.get("/analizar_actividad_firewall")
def analizar_actividad_firewall():
    server = 'localhost'
    log_type = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    ahora = datetime.datetime.now()
    bloqueos = []

    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
    except:
        return {"status": "error", "aviso": "⚠️ No se pudo acceder al registro del firewall. Puede que no esté habilitado."}

    try:
        while True:
            eventos = win32evtlog.ReadEventLog(handle, flags, 0)
            if not eventos:
                break
            for evento in eventos:
                fecha = evento.TimeGenerated
                if (ahora - fecha).total_seconds() > 3600:
                    continue
                detalles = evento.StringInserts
                if detalles and len(detalles) >= 6:
                    direccion_remota = detalles[3]
                    puerto = detalles[4]
                    accion = detalles[5]
                    if accion.lower() == "block":
                        bloqueos.append(f"🚫 Bloqueo de conexión desde {direccion_remota}:{puerto} ({fecha})")
    finally:
        win32evtlog.CloseEventLog(handle)

    if bloqueos:
        return {"status": "sospechoso", "aviso": "\n".join(bloqueos[:6])}
    else:
        return {"status": "seguro", "aviso": "✅ No se detectaron bloqueos recientes en el firewall."}

@app.get("/analizar_cambios_usuarios")
def analizar_cambios_usuarios():
    server = 'localhost'
    log_type = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    event_ids = [4720, 4726, 4732]

    ahora = datetime.datetime.now()
    cambios = []

    handle = win32evtlog.OpenEventLog(server, log_type)
    try:
        while True:
            registros = win32evtlog.ReadEventLog(handle, flags, 0)
            if not registros:
                break
            for evento in registros:
                if evento.EventID in event_ids:
                    fecha = evento.TimeGenerated
                    if (ahora - fecha).total_seconds() > 3600:
                        continue
                    detalles = evento.StringInserts
                    if not detalles:
                        continue
                    if evento.EventID == 4720:
                        cambios.append(f"🟢 Se creó una cuenta de usuario: {detalles[0]} ({fecha})")
                    elif evento.EventID == 4726:
                        cambios.append(f"🔴 Se eliminó una cuenta de usuario: {detalles[0]} ({fecha})")
                    elif evento.EventID == 4732:
                        cambios.append(f"🟡 Se añadió un usuario a un grupo: {detalles[0]} en {detalles[-1]} ({fecha})")
    finally:
        win32evtlog.CloseEventLog(handle)

    if cambios:
        return {"status": "sospechoso", "aviso": "\n".join(cambios)}
    else:
        return {"status": "seguro", "aviso": "✅ No se detectaron cambios recientes en cuentas de usuario."}

@app.get("/analizar_errores_app")
def analizar_errores_app():
    server = 'localhost'
    log_type = 'Application'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    ahora = datetime.datetime.now()
    errores = []
    fuentes = []
    fuentes_criticas = ["Windows Defender", "PowerShell", "svchost", "Winlogon", "lsass", "SecurityHealthService"]

    handle = win32evtlog.OpenEventLog(server, log_type)
    try:
        while True:
            registros = win32evtlog.ReadEventLog(handle, flags, 0)
            if not registros:
                break
            for evento in registros:
                fecha = evento.TimeGenerated
                if (ahora - fecha).total_seconds() > 3600:
                    continue
                if evento.EventType == 1:
                    fuente = evento.SourceName
                    fuentes.append(fuente)
                    if fuente in fuentes_criticas:
                        mensaje = evento.StringInserts[0] if evento.StringInserts else "(sin detalles)"
                        errores.append(f"❌ [{fuente}] {mensaje} ({fecha})")
    finally:
        win32evtlog.CloseEventLog(handle)

    repetidos = Counter(fuentes)
    frecuentes = [f for f, c in repetidos.items() if c >= 3]
    if frecuentes:
        errores.insert(0, "⚠️ Se detectaron errores repetidos en las siguientes aplicaciones: " + ", ".join(frecuentes))

    if errores:
        return {"status": "sospechoso", "aviso": "\n".join(errores[:6])}
    else:
        return {"status": "seguro", "aviso": "✅ No se detectaron errores relevantes en las aplicaciones."}

@app.get("/detectar_patrones")
def detectar_patrones():
    server = 'localhost'
    log_type = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    event_ids = [4625, 4624, 4672, 4728, 4724, 4688]

    eventos_por_usuario = defaultdict(list)
    ahora = datetime.datetime.now()

    handle = win32evtlog.OpenEventLog(server, log_type)
    try:
        while True:
            registros = win32evtlog.ReadEventLog(handle, flags, 0)
            if not registros:
                break
            for evento in registros:
                if evento.EventID in event_ids:
                    fecha = evento.TimeGenerated
                    if (ahora - fecha).total_seconds() > 1800:
                        continue
                    detalles = evento.StringInserts
                    if detalles and len(detalles) >= 6:
                        usuario = detalles[5]
                        eventos_por_usuario[usuario].append((fecha, evento.EventID))
    finally:
        win32evtlog.CloseEventLog(handle)

    alertas = []
    resumenes = []
    predicciones = []
    for usuario, eventos in eventos_por_usuario.items():
        eventos.sort()
        ids = [e[1] for e in eventos]

        cuenta = {"4625": 0, "4624": 0, "4672": 0, "4728": 0, "4724": 0, "4688": 0}
        for _, eid in eventos:
            if str(eid) in cuenta:
                cuenta[str(eid)] += 1

        if model_patron:
            entrada = np.array([[cuenta[e] for e in ["4625", "4624", "4672", "4728", "4724", "4688"]]])
            pred = model_patron.predict(entrada)[0]
            if pred == 1:
                predicciones.append({
                    "usuario": usuario,
                    "riesgo": "⚠️ Riesgo elevado detectado",
                    "evento_summary": cuenta
                })

        if ids.count(4625) >= 3 and 4624 in ids:
            alerta = {
                "usuario": usuario,
                "tipo": "Fuerza bruta",
                "descripcion": f"Múltiples fallos de inicio de sesión seguidos de un acceso exitoso detectados para el usuario {usuario}"
            }
            if 4672 in ids:
                alerta["descripcion"] += ", además recibió privilegios elevados."
                resumenes.append(f"El usuario {usuario} intentó iniciar sesión múltiples veces sin éxito, finalmente accedió correctamente y obtuvo privilegios elevados.")
            else:
                resumenes.append(f"El usuario {usuario} realizó múltiples intentos fallidos de inicio de sesión y logró acceder con éxito posteriormente.")
            alertas.append(alerta)

        for i, (fecha, eid) in enumerate(eventos):
            if eid == 4728:
                for j in range(i+1, len(eventos)):
                    if eventos[j][1] in [4724, 4688]:
                        diferencia = (eventos[j][0] - fecha).total_seconds()
                        if diferencia <= 600:
                            alertas.append({
                                "usuario": usuario,
                                "tipo": "Escalada de privilegios",
                                "descripcion": f"El usuario {usuario} fue añadido al grupo Administradores y realizó acciones privilegiadas {int(diferencia)} segundos después."
                            })
                            resumenes.append(f"El usuario {usuario} fue añadido al grupo de administradores y realizó acciones privilegiadas {int(diferencia/60)} minutos después.")
                        break

    return {"alertas": alertas, "resumen": resumenes, "predicciones": predicciones}

@app.get("/analizar_conexiones_remotas")
def analizar_conexiones_remotas():
    server = 'localhost'
    log_type = 'Security'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    ahora = datetime.datetime.now()
    conexiones = []

    handle = win32evtlog.OpenEventLog(server, log_type)
    try:
        while True:
            eventos = win32evtlog.ReadEventLog(handle, flags, 0)
            if not eventos:
                break
            for evento in eventos:
                if evento.EventID == 4624:
                    fecha = evento.TimeGenerated
                    if (ahora - fecha).total_seconds() > 3600:
                        continue
                    detalles = evento.StringInserts
                    if detalles and len(detalles) >= 11:
                        tipo_inicio = detalles[8]
                        ip_origen = detalles[10]
                        if tipo_inicio == "10" and ip_origen != "127.0.0.1":
                            try:
                                ip_obj = ipaddress.ip_address(ip_origen)
                                if not ip_obj.is_private:
                                    conexiones.append(f"🚨 Conexión remota desde IP EXTERNA detectada: {ip_origen} ({fecha})")
                                else:
                                    conexiones.append(f"🔌 Conexión remota desde red local: {ip_origen} ({fecha})")
                            except:
                                conexiones.append(f"❓ IP no válida o desconocida detectada: {ip_origen} ({fecha})")
    finally:
        win32evtlog.CloseEventLog(handle)

    if conexiones:
        return {"status": "sospechoso", "aviso": "\n".join(conexiones)}
    else:
        return {"status": "seguro", "aviso": "✅ No se detectaron conexiones remotas sospechosas en la última hora."}
