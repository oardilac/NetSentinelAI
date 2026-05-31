"""
04_eval.py - MÓDULO 4: Entrenamiento Final y Auditoría de Falsos Negativos
==========================================================================
- Entrena el modelo campeón con el número de variables consolidado por tarea.
- Genera el gráfico de pastel interactivo analizando las evasiones del modelo binario.
"""

import os
import time
import joblib
import pandas as pd
import numpy as np

import plotly.figure_factory as ff
import plotly.express as px

from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             matthews_corrcoef, confusion_matrix)
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler

# Importación de algoritmos para la instanciación dinámica
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
import lightgbm as lgb

from training_config import (
    RANDOM_STATE,
    UNDER_SAMPLE_TARGET,
    OVER_SAMPLE_TARGET,
    SMOTE_K_NEIGHBORS,
    CLEAN_DATA_DIR,
    MODELS_DIR,
    RESULTS_DIR,
    PLOTS_DIR,
    build_resampling_strategies,
)

def analyze_binary_false_negatives(y_test_binary, y_pred_binary):
    print("\n>>> [Módulo 4] Extrayendo proporciones de Falsos Negativos en Capa Binaria...")
    
    # Cruce directo con los strings de ataques originales preservados por el Módulo 1
    y_test_attacks_raw = pd.read_csv(f"{CLEAN_DATA_DIR}/binary/binary_y_test_attacks.csv").values.ravel()
    
    df_audit = pd.DataFrame({
        'Real_Binary': y_test_binary,
        'Pred_Binary': y_pred_binary,
        'Ataque_Especifico': y_test_attacks_raw
    })
    
    # Falso Negativo: Era un ataque real (1) pero el modelo predijo tráfico normal (0)
    df_fn = df_audit[(df_audit['Real_Binary'] == 1) & (df_audit['Pred_Binary'] == 0)].copy()
    
    if df_fn.empty:
        print("    ¡Excelente! El modelo binario capturó el 100% de los ataques (0 Falsos Negativos).")
        return

    total_fn = len(df_fn)
    total_attacks = (y_test_binary == 1).sum()
    print(f"    Evasiones totales registradas: {total_fn:,} de {total_attacks:,} ataques en Test ({ (total_fn/total_attacks)*100 :.2f}%)")
    
    df_report = df_fn['Ataque_Especifico'].value_counts().reset_index(name='Cantidad_Evadida')
    df_report.rename(columns={df_report.columns[0]: 'Tipo_de_Ataque'}, inplace=True)
    df_report['Porcentaje_del_Total_FN'] = (df_report['Cantidad_Evadida'] / total_fn) * 100
    df_report.to_csv(os.path.join(RESULTS_DIR, "binary_false_negatives_distribution.csv"), index=False)
    
    # Gráfico interactivo circular de dona
    fig = px.pie(df_report, values='Cantidad_Evadida', names='Tipo_de_Ataque',
                 title=f"Distribución de Intrusiones Evadidas (Falsos Negativos)<br><sup>Auditoría sobre un total de {total_fn:,} fallas de detección en el Sniffer</sup>",
                 hover_data=['Porcentaje_del_Total_FN'], color_discrete_sequence=px.colors.qualitative.Pastel)
    fig.update_traces(textinfo='percent+label', hole=0.3)
    fig.update_layout(template="plotly_white")
    fig.write_html(os.path.join(PLOTS_DIR, "binary_false_negatives_pie.html"))
    print(f"    [Gráfica Guardada] -> {PLOTS_DIR}/binary_false_negatives_pie.html")

def train_and_eval_final(task_type: str):
    print(f"\n>>> [Módulo 4] Ajustando modelo campeón definitivo para: {task_type.upper()}")
    
    # Recuperamos metadatos guardados por el Grid Search
    meta = joblib.load(os.path.join(RESULTS_DIR, f"champion_metadata_{task_type}.pkl"))
    selected_features = meta['features_used']
    
    # ──────────────────────────────────────────────────────────────────────────
    # CORRECCIÓN: Deducción e instanciación dinámica del modelo
    # ──────────────────────────────────────────────────────────────────────────
    # Limpiamos el prefijo 'clf__' de los parámetros guardados
    clf_params = {k.replace('clf__', ''): v for k, v in meta['best_params'].items()}
    
    # Buscamos la huella digital (hiperparámetros únicos) para saber qué modelo fue el campeón
    if 'num_leaves' in clf_params:
        model_name = "LightGBM"
        final_clf = lgb.LGBMClassifier(random_state=RANDOM_STATE, n_jobs=-1, verbose=-1)
    elif 'min_samples_split' in clf_params:
        model_name = "RandomForest"
        final_clf = RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1)
    else:
        model_name = "XGBoost"
        final_clf = XGBClassifier(random_state=RANDOM_STATE, n_jobs=-1, eval_metric='logloss')

    # Inyectamos los parámetros ganadores al modelo limpio
    final_clf.set_params(**clf_params)
    print(f"    Modelo elegido: {model_name} entrenando con {meta['n_features']} variables.")
    
    # Carga de datos
    base_path = os.path.join(CLEAN_DATA_DIR, task_type)
    X_train = pd.read_csv(f"{base_path}/{task_type}_X_train.csv")[selected_features]
    y_train = pd.read_csv(f"{base_path}/{task_type}_y_train.csv").values.ravel()
    X_test = pd.read_csv(f"{base_path}/{task_type}_X_test.csv")[selected_features]
    y_test = pd.read_csv(f"{base_path}/{task_type}_y_test.csv").values.ravel()

    if task_type == "multi":
        le = joblib.load(os.path.join(RESULTS_DIR, "label_encoder_multi.pkl"))
        y_train = le.transform(y_train)
        y_test = le.transform(y_test)
        class_names = le.classes_.tolist()
    else:
        class_names = ["BENIGN", "Ataque"]

    # Escalado — Preservar feature names después del escalado
    scaler = RobustScaler()
    X_tr_scaled = scaler.fit_transform(X_train.values)
    X_te_scaled = scaler.transform(X_test.values)

    # Reconstruir DataFrames con feature names para evitar warning de sklearn
    X_tr_scaled = pd.DataFrame(X_tr_scaled, columns=X_train.columns)
    X_te_scaled = pd.DataFrame(X_te_scaled, columns=X_test.columns)

    # Balanceo adaptativo
    if task_type == "binary":
        X_bal, y_bal = RandomUnderSampler(sampling_strategy="majority", random_state=RANDOM_STATE).fit_resample(X_tr_scaled, y_train)
    else:
        under_strat, over_strat = build_resampling_strategies(y_train)
        X_bal, y_bal = X_tr_scaled, y_train
        if under_strat: X_bal, y_bal = RandomUnderSampler(sampling_strategy=under_strat, random_state=RANDOM_STATE).fit_resample(X_bal, y_bal)
        if over_strat: X_bal, y_bal = SMOTE(sampling_strategy=over_strat, k_neighbors=SMOTE_K_NEIGHBORS, random_state=RANDOM_STATE).fit_resample(X_bal, y_bal)

    # Entrenamiento del modelo configurado
    t0 = time.time()
    final_clf.fit(X_bal, y_bal)
    train_time = time.time() - t0

    # Inferencia
    y_pred = final_clf.predict(X_te_scaled)

    # Métricas
    avg_method = "binary" if task_type == "binary" else "weighted"
    metrics = {
        "Tarea": task_type,
        "Modelo_Elegido": model_name,
        "Accuracy": accuracy_score(y_test, y_pred),
        "Precision": precision_score(y_test, y_pred, average=avg_method, zero_division=0),
        "Recall": recall_score(y_test, y_pred, average=avg_method, zero_division=0),
        "F1_Score": f1_score(y_test, y_pred, average=avg_method, zero_division=0),
        "MCC": matthews_corrcoef(y_test, y_pred),
        "Tiempo_Entrenamiento_s": round(train_time, 2)
    }
    print(f"    Rendimiento consolidado F1: {metrics['F1_Score']:.4f}")

    # Guardado de artefactos
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(final_clf, os.path.join(MODELS_DIR, f"champion_model_{task_type}.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, f"production_scaler_{task_type}.pkl"))

    # Matrices de confusión
    cm = confusion_matrix(y_test, y_pred)
    cm_text = [[str(y) for y in x] for x in cm[::-1]]
    fig = ff.create_annotated_heatmap(z=cm[::-1], x=class_names, y=class_names[::-1], annotation_text=cm_text, colorscale='Cividis', showscale=True)
    fig.update_layout(title=f"Matriz de Confusión — {task_type.upper()}", xaxis_title="Predicho", yaxis_title="Real", template="plotly_white")
    fig.write_html(os.path.join(PLOTS_DIR, f"confusion_matrix_{task_type}.html"))

    # Auditoría exclusiva del binario
    if task_type == "binary":
        analyze_binary_false_negatives(y_test, y_pred)

    return metrics

if __name__ == "__main__":
    r_bin = train_and_eval_final("binary")
    r_mul = train_and_eval_final("multi")
    pd.DataFrame([r_bin, r_mul]).to_csv(os.path.join(RESULTS_DIR, "production_final_metrics.csv"), index=False)
    print("\n>>> Pipeline finalizado con éxito. Reportes HTML disponibles en './Results/plots'.")