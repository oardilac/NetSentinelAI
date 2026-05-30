import logging
import os
import warnings

import lightgbm as lgb
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import shap

warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)

CLEAN_DATA_DIR = "./DataClean"
REDUCED_DATA_DIR = "./DataReduced"
RESULTS_DIR = "./Results/plots/shap"
SHAP_SAMPLE_CAP = 15000  # max rows for SHAP computation (performance vs accuracy trade-off)
RANDOM_STATE = 42

def generate_plotly_html(task_type, shap_values_matrix, feature_names, class_names, top_n):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    if len(shap_values_matrix.shape) == 3:
        global_importance = np.abs(shap_values_matrix).mean(axis=(0, 2))
        class_importance = {class_names[c]: np.abs(shap_values_matrix[:, :, c]).mean(axis=0) for c in range(len(class_names))}
    else:
        global_importance = np.abs(shap_values_matrix).mean(axis=0)
        class_importance = {"Ataque (Clase 1)": global_importance}

    indices_ordenados = np.argsort(global_importance)[::-1][:top_n]
    top_features = [feature_names[i] for i in indices_ordenados]
    top_global_vals = global_importance[indices_ordenados]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=top_global_vals[::-1], y=top_features[::-1], orientation='h',
        name='Importancia Global', marker=dict(color='rgba(55, 128, 191, 0.7)')
    ))

    buttons = [dict(label="Importancia Global", method="update", args=[{"x": [top_global_vals[::-1]], "y": [top_features[::-1]], "marker.color": 'rgba(55, 128, 191, 0.7)'}])]
    for nombre_clase, valores in class_importance.items():
        vals_clase = valores[indices_ordenados]
        buttons.append(dict(label=f"Impacto en: {nombre_clase}", method="update", args=[{"x": [vals_clase[::-1]], "y": [top_features[::-1]], "marker.color": 'rgba(219, 64, 82, 0.7)'}]))

    fig.update_layout(
        updatemenus=[dict(active=0, buttons=buttons, direction="down", x=0.1, y=1.15)],
        title=dict(text=f"Visor Analítico SHAP — Dataset {task_type.upper()}"),
        plot_bgcolor='rgba(0,0,0,0)', height=650, width=950, margin=dict(l=180, r=30, t=100, b=50)
    )

    html_file = os.path.join(RESULTS_DIR, f"shap_interactive_report_{task_type}.html")
    fig.write_html(html_file)
    return top_features

def apply_shap_reduction(task_type="binary", top_n=15):
    print(f"\n>>> [2/4] Selección SHAP ({task_type.upper()}) | Top: {top_n}")
    os.makedirs(REDUCED_DATA_DIR, exist_ok=True)

    base = os.path.join(CLEAN_DATA_DIR, task_type)
    X_train_raw = pd.read_csv(os.path.join(base, f"{task_type}_X_train.csv"))
    y_train     = pd.read_csv(os.path.join(base, f"{task_type}_y_train.csv")).values.ravel()
    X_test_raw  = pd.read_csv(os.path.join(base, f"{task_type}_X_test.csv"))
    y_test      = pd.read_csv(os.path.join(base, f"{task_type}_y_test.csv")).values.ravel()

    orig_tr = X_train_raw["Original_Label"].values if "Original_Label" in X_train_raw.columns else None
    orig_te = X_test_raw["Original_Label"].values if "Original_Label" in X_test_raw.columns else None
    if orig_tr is None:
        logger.warning("'Original_Label' column not found in X_train — audit column will be missing")
    if orig_te is None:
        logger.warning("'Original_Label' column not found in X_test — audit column will be missing")

    X_train = X_train_raw.drop(columns=["Original_Label"], errors="ignore")
    X_test  = X_test_raw.drop(columns=["Original_Label"], errors="ignore")

    model = lgb.LGBMClassifier(random_state=RANDOM_STATE, n_jobs=-1, verbose=-1)
    model.fit(X_train, y_train)

    X_sample = shap.sample(X_train, SHAP_SAMPLE_CAP) if len(X_train) > SHAP_SAMPLE_CAP else X_train
    explainer = shap.TreeExplainer(model)
    shap_output = explainer(X_sample)

    class_names = [] if task_type == "binary" else [str(c) for c in np.unique(y_train)]
    shap_matrix = shap_output.values[:, :, 1] if task_type == "binary" and len(shap_output.shape) == 3 else shap_output.values

    top_features = generate_plotly_html(task_type, shap_matrix, X_train.columns.tolist(), class_names, top_n)
    
    X_train_red = X_train[top_features].copy()
    X_test_red  = X_test[top_features].copy()

    if orig_tr is not None: X_train_red["Original_Label"] = orig_tr
    if orig_te is not None: X_test_red["Original_Label"] = orig_te

    X_train_red.to_csv(os.path.join(REDUCED_DATA_DIR, f"{task_type}_X_train_red.csv"), index=False)
    X_test_red.to_csv(os.path.join(REDUCED_DATA_DIR, f"{task_type}_X_test_red.csv"), index=False)
    pd.DataFrame(y_train).to_csv(os.path.join(REDUCED_DATA_DIR, f"{task_type}_y_train.csv"), index=False)
    pd.DataFrame(y_test).to_csv(os.path.join(REDUCED_DATA_DIR, f"{task_type}_y_test.csv"), index=False)

if __name__ == "__main__":
    apply_shap_reduction("binary", top_n=10)
    apply_shap_reduction("multi", top_n=10)
    print(">>> Módulo 2 completado.")