"""
03_gridsearch.py - MÓDULO 3: Grid Search con Atributos Independientes por TAREA
================================================================================
- Permite configurar de manera independiente cuántas características usa el modelo BINARY y el MULTI.
- Garantiza que todos los algoritmos de una misma tarea compitan bajo una matriz idéntica.
"""

import os
import joblib
import pandas as pd
import numpy as np
import plotly.express as px
from collections import Counter

from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, RobustScaler
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
import lightgbm as lgb

from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline

from training_config import (
    RANDOM_STATE,
    UNDER_SAMPLE_TARGET,
    OVER_SAMPLE_TARGET,
    SMOTE_K_NEIGHBORS,
    CV_SPLITS,
    CV_SCORING,
    CLEAN_DATA_DIR,
    RESULTS_DIR,
    PLOTS_DIR,
)

# ──────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN INDEPENDIENTE DE CARACTERÍSTICAS POR TAREA (PRODUCCIÓN)
# ──────────────────────────────────────────────────────────────────────────
TASK_FEATURE_COUNTS = {
    'binary': 15,  # El modelo binario (sniffer rápido) usará el Top 15 de SHAP
    'multi': 15    # El modelo multiclase (diagnóstico) usará el Top 15 de SHAP
}

def run_grid_search(task_type: str):
    # Extraemos el número de variables asignado de forma independiente a esta tarea
    n_feats = TASK_FEATURE_COUNTS[task_type]
    print(f"\n>>> [Módulo 3] Iniciando Grid Search para {task_type.upper()} usando el Top {n_feats} atributos de SHAP")
    
    base_path = os.path.join(CLEAN_DATA_DIR, task_type)
    ranked_features = joblib.load(os.path.join(RESULTS_DIR, f"ranked_features_list_{task_type}.pkl"))
    
    X_train_raw = pd.read_csv(f"{base_path}/{task_type}_X_train.csv")
    y_train = pd.read_csv(f"{base_path}/{task_type}_y_train.csv").values.ravel()

    if task_type == "multi":
        le = LabelEncoder()
        y_train = le.fit_transform(y_train)
        joblib.dump(le, os.path.join(RESULTS_DIR, "label_encoder_multi.pkl"))

    # ──────────────────────────────────────────────────────────────────────────
    # FILTRADO PREVIO AL BUCLE: Garantiza homogeneidad para todos los modelos
    # ──────────────────────────────────────────────────────────────────────────
    selected_cols = ranked_features[:n_feats]
    X_train_filtered = X_train_raw[selected_cols].copy()
    print(f"    Matriz de entrenamiento reducida a dimensiones: {X_train_filtered.shape}")

    cv = StratifiedKFold(n_splits=CV_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    
    models_spec = {
        'LightGBM': {
            'clf': lgb.LGBMClassifier(random_state=RANDOM_STATE, n_jobs=-1, verbose=-1),
            'grid': {
                'clf__n_estimators': [100, 200, 300],
                'clf__learning_rate': [0.01, 0.05, 0.1],
                'clf__num_leaves': [31, 63]
            }
        },
        'XGBoost': {
            'clf': XGBClassifier(random_state=RANDOM_STATE, n_jobs=-1, eval_metric='logloss'),
            'grid': {
                'clf__n_estimators': [100, 200, 300],
                'clf__max_depth': [5, 7, 10],
                'clf__learning_rate': [0.05, 0.1]
            }
        },
        'RandomForest': {
            'clf': RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1),
            'grid': {
                'clf__n_estimators': [150, 300],
                'clf__max_depth': [15, 25, None],
                'clf__min_samples_split': [2, 5]
            }
        }
    }

    cv_results = []
    best_models_metadata = {}

    # Ahora todos los modelos se ajustan sobre la misma X_train_filtered
    for name, spec in models_spec.items():
        print(f"  -> Evaluando arquitectura: {name}...")
        
        counts = Counter(y_train)
        steps = [('scaler', RobustScaler())]
        
        if task_type == "binary":
            steps.append(('under', RandomUnderSampler(sampling_strategy="majority", random_state=RANDOM_STATE)))
        else:
            under_strat = {k: UNDER_SAMPLE_TARGET for k, v in counts.items() if v > UNDER_SAMPLE_TARGET}
            over_strat = {k: OVER_SAMPLE_TARGET for k, v in counts.items() if v < OVER_SAMPLE_TARGET}
            if under_strat: steps.append(('under', RandomUnderSampler(sampling_strategy=under_strat, random_state=RANDOM_STATE)))
            if over_strat: steps.append(('smote', SMOTE(sampling_strategy=over_strat, k_neighbors=SMOTE_K_NEIGHBORS, random_state=RANDOM_STATE)))
            
        steps.append(('clf', spec['clf']))
        pipeline = ImbPipeline(steps=steps)
        
        grid = GridSearchCV(pipeline, spec['grid'], cv=cv, scoring=CV_SCORING, n_jobs=-1)
        grid.fit(X_train_filtered, y_train)
        
        print(f"     Mejor F1-Macro: {grid.best_score_:.4f} | Hiperparámetros optimizados: {grid.best_params_}")
        
        for fold in range(cv.n_splits):
            score = grid.cv_results_[f'split{fold}_test_score'][grid.best_index_]
            cv_results.append({"Modelo": name, "Fold": f"Fold {fold+1}", "F1_Macro": score})
            
        best_models_metadata[name] = {
            'best_params': grid.best_params_,
            'best_score': grid.best_score_,
            'features_used': selected_cols,
            'n_features': n_feats
        }

    champion_name = max(best_models_metadata, key=lambda k: best_models_metadata[k]['best_score'])
    print(f"  >>> Arquitectura Ganadora Definitiva para {task_type.upper()}: {champion_name}")
    
    # Guardamos la configuración ganadora para el Módulo 4
    joblib.dump(best_models_metadata[champion_name], os.path.join(RESULTS_DIR, f"champion_metadata_{task_type}.pkl"))
    
    df_cv = pd.DataFrame(cv_results)
    fig = px.box(df_cv, x="Modelo", y="F1_Macro", color="Modelo", points="all",
                 title=f"Rendimiento Cruzado Homogéneo ({n_feats} Atributos) — {task_type.upper()}")
    fig.update_layout(template="plotly_white")
    fig.write_html(os.path.join(PLOTS_DIR, f"cv_stability_{task_type}.html"))

if __name__ == "__main__":
    run_grid_search("binary")
    run_grid_search("multi")
    print(">>> MÓDULO 3: Completado con éxito.\n")