import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# Cargar el CSV que generamos
df = pd.read_csv("eventos_resumen_entrenamiento.csv")

# Definir las columnas que usaremos como entrada
features = ["4625", "4624", "4672", "4728", "4724", "4688"]

# Separar X e y
X = df[features].values
y = df["etiqueta"].values

# Entrenar el modelo
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Guardar el modelo entrenado
joblib.dump(model, "threat_pattern_model.pkl")

print("✅ Modelo threat_pattern_model.pkl generado con éxito.")