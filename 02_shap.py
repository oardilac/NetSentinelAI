"""
02_shap.py - MÓDULO 2: Tablero SHAP Centralizado con Menú Desplegable
=====================================================================
- Calcula las contribuciones SHAP globales y por clase (Multiclase).
- NUEVO: Genera UN SOLO archivo HTML interactivo con un dropdown para cambiar de ataque.
"""

import os
import pandas as pd
import numpy as np
import lightgbm as lgb
import shap
import joblib
import plotly.graph_objects as go
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

CLEAN_DATA_DIR = "./DataClean"
RESULTS_DIR = "./Results"
PLOTS_DIR = "./Results/plots"
SHAP_SAMPLE_SIZE = 30000  

def run_shap_selection(task_type: str):
    print(f"\n>>> [Módulo 2] Calculando espectro SHAP para: {task_type.upper()}")
    base_path = os.path.join(CLEAN_DATA_DIR, task_type)
    X_train = pd.read_csv(f"{base_path}/{task_type}_X_train.csv")
    y_train = pd.read_csv(f"{base_path}/{task_type}_y_train.csv").values.ravel()

    if task_type == "binary":
        class_names = ["BENIGN", "Ataque"]
    else:
        le = LabelEncoder()
        y_train = le.fit_transform(y_train)
        class_names = le.classes_.tolist()

    if len(X_train) > SHAP_SAMPLE_SIZE:
        X_sample, _, y_sample, _ = train_test_split(X_train, y_train, train_size=SHAP_SAMPLE_SIZE, stratify=y_train, random_state=42)
    else:
        X_sample, y_sample = X_train, y_train

    model = lgb.LGBMClassifier(n_estimators=60, max_depth=5, random_state=42, n_jobs=-1, verbose=-1)
    model.fit(X_sample, y_sample)

    print("    Calculando TreeExplainer...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)

    # 1. PROCESAMIENTO GLOBAL
    if isinstance(shap_values, list):
        mean_shap = np.abs(np.array(shap_values)).mean(axis=(0, 1))
    elif len(shap_values.shape) == 3:
        mean_shap = np.abs(shap_values).mean(axis=(0, 2)) if shap_values.shape[2] == len(class_names) else np.abs(shap_values).mean(axis=0)
    else:
        mean_shap = np.abs(shap_values).mean(axis=0)

    df_shap_global = pd.DataFrame({"Caracteristica": X_train.columns, "Impacto_SHAP": mean_shap}).sort_values(by="Impacto_SHAP", ascending=False)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(PLOTS_DIR, exist_ok=True)
    df_shap_global.to_csv(os.path.join(RESULTS_DIR, f"shap_ranked_features_{task_type}.csv"), index=False)
    joblib.dump(df_shap_global["Caracteristica"].tolist(), os.path.join(RESULTS_DIR, f"ranked_features_list_{task_type}.pkl"))

    # 2. CONSTRUCCIÓN DEL DASHBOARD INTERACTIVO (CON DROPDOWN)
    print("    Estructurando Dashboard interactivo de atributos...")
    fig = go.Figure()

    # Añadir primera traza: Importancia Global (Siempre visible por defecto)
    df_g_top = df_shap_global.head(15).sort_values(by="Impacto_SHAP", ascending=True)
    fig.add_trace(go.Bar(
        x=df_g_top["Impacto_SHAP"], y=df_g_top["Caracteristica"],
        orientation='h', name="Global", marker=dict(color=df_g_top["Impacto_SHAP"], colorscale='Viridis'),
        visible=True
    ))

    buttons = [
        dict(label="Espectro Global", method="update", args=[{"visible": [True] + [False]*len(class_names)}, 
             {"title": f"Atributos Críticos Globales — {task_type.upper()}"}])
    ]

    # Añadir trazas independientes ocultas si es Multiclase
    if task_type == "multi":
        for idx, class_name in enumerate(class_names):
            if isinstance(shap_values, list): class_matrix = shap_values[idx]
            elif len(shap_values.shape) == 3: class_matrix = shap_values[:, :, idx] if shap_values.shape[2] == len(class_names) else shap_values[idx, :, :]
            else: continue

            mean_class_shap = np.abs(class_matrix).mean(axis=0)
            df_c = pd.DataFrame({"Caracteristica": X_train.columns, "Impacto_SHAP": mean_class_shap})
            df_c_top = df_c.sort_values(by="Impacto_SHAP", ascending=True).tail(15)

            # Agregar la barra al gráfico (oculta al inicio)
            fig.add_trace(go.Bar(
                x=df_c_top["Impacto_SHAP"], y=df_c_top["Caracteristica"],
                orientation='h', name=class_name, marker=dict(color=df_c_top["Impacto_SHAP"], colorscale='Oranges'),
                visible=False
            ))

            # Configurar el botón lógico para este ataque específico
            visibility_mask = [False] * (len(class_names) + 1)
            visibility_mask[idx + 1] = True # Activamos solo esta traza
            
            buttons.append(dict(
                label=f"Firma: {class_name}", method="update",
                args=[{"visible": visibility_mask}, {"title": f"Atributos Exclusivos para Identificar: <span style='color:red'>{class_name}</span>"}]
            ))

    # Integrar el menú desplegable en el diseño
    fig.update_layout(
        updatemenus=[dict(active=0, buttons=buttons, direction="down", pad={"r": 10, "t": 10}, showactive=True, x=0.1, xanchor="left", y=1.15, yanchor="top")],
        title=f"Dashboard de Atributos Críticos — {task_type.upper()}",
        xaxis_title="Importancia Absoluta (SHAP)", yaxis_title="Métrica del Flujo de Red",
        template="plotly_white", height=650
    )

    fig.write_html(os.path.join(PLOTS_DIR, f"shap_dashboard_{task_type}.html"))
    print(f"    [Éxito] Dashboard unificado guardado en -> {PLOTS_DIR}/shap_dashboard_{task_type}.html")

if __name__ == "__main__":
    run_shap_selection("binary")
    run_shap_selection("multi")