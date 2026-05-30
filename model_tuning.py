"""
model_tuning.py  –  CIC-IDS2017  |  La Arena de Modelos (GridSearch & CV)  [Módulo 3]
======================================================================
Somete a todos los candidatos a un GridSearchCV garantizando que SMOTE
solo actúe en los pliegues de entrenamiento. Guarda los mejores estimadores
y genera mapas de calor de la búsqueda de parámetros.

Pipeline de entrenamiento:
    Módulo 1: data_preparation.py  →  DataClean/
    Módulo 2: feature_selection.py →  DataReduced/
    Módulo 3: model_tuning.py      →  Results/models/tuned/
    Módulo 4: final_evaluation.py  →  Models/ (promoción + metadata)
"""

import os
import joblib
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble        import RandomForestClassifier
from sklearn.neural_network  import MLPClassifier
from sklearn.preprocessing   import LabelEncoder, RobustScaler
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from xgboost                 import XGBClassifier

from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling  import SMOTE
from imblearn.pipeline       import Pipeline as ImbPipeline

warnings.filterwarnings("ignore")

DATA_DIR     = "./DataReduced"
MODELS_DIR   = "./Results/models/tuned"
PLOTS_DIR    = "./Results/plots/tuning"
RANDOM_STATE = 42
CV_SPLITS    = 3

def plot_grid_heatmap(cv_results, model_name, task_type, param_x, param_y):
    """Genera un mapa de calor 2D para evaluar estadísticamente el GridSearch."""
    df = pd.DataFrame(cv_results)
    if param_x not in df.columns or param_y not in df.columns:
        return # Skip if params don't match exactly for 2D plot
        
    pivot_table = df.pivot_table(values='mean_test_score', index=param_y, columns=param_x, aggfunc=np.mean)
    
    plt.figure(figsize=(7, 5))
    sns.heatmap(pivot_table, annot=True, cmap='viridis', fmt=".4f")
    plt.title(f"GridSearch: {model_name} ({task_type.upper()})", fontweight="bold")
    plt.xlabel(param_x.replace("param_clf__", ""))
    plt.ylabel(param_y.replace("param_clf__", ""))
    
    os.makedirs(PLOTS_DIR, exist_ok=True)
    plt.savefig(os.path.join(PLOTS_DIR, f"heatmap_{model_name}_{task_type}.png"), dpi=150, bbox_inches="tight")
    plt.close()

def run_tuning_arena(task_type="binary"):
    print(f"\n{'-'*60}\nINICIANDO TORNEO GRIDSEARCH: {task_type.upper()}\n{'-'*60}")
    
    X_train_raw = pd.read_csv(os.path.join(DATA_DIR, f"{task_type}_X_train_red.csv"))
    y_train_raw = pd.read_csv(os.path.join(DATA_DIR, f"{task_type}_y_train.csv")).values.ravel()

    X_train = X_train_raw.drop(columns=["Original_Label"], errors="ignore")
    
    le = None
    if task_type == "multi":
        le = LabelEncoder()
        y_train = le.fit_transform(y_train_raw)
        # Balance all classes towards majority to address multi-class imbalance
        SMOTE_STRATEGY = "not majority"
        UNDER_STRATEGY = "majority"
        xgb_metric = "mlogloss"
    else:
        y_train = y_train_raw.astype(int)
        # Oversample minority (attack) to 40% of majority (benign), then undersample majority to 80%
        SMOTE_STRATEGY = 0.40
        UNDER_STRATEGY = 0.80
        xgb_metric = "logloss"

    # Definir modelos base y sus grillas (usando prefijo 'clf__' por el Pipeline)
    candidates = {
        "RandomForest": {
            "model": RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1),
            "grid": {'clf__n_estimators': [50, 80], 'clf__max_depth': [10, 15]},
            "plot_params": ('param_clf__n_estimators', 'param_clf__max_depth')
        },
        "XGBoost": {
            "model": XGBClassifier(random_state=RANDOM_STATE, n_jobs=-1, eval_metric=xgb_metric),
            "grid": {'clf__n_estimators': [60, 100], 'clf__max_depth': [5, 7], 'clf__learning_rate': [0.1]},
            "plot_params": ('param_clf__n_estimators', 'param_clf__max_depth')
        },
        "MLP": {
            "model": MLPClassifier(early_stopping=True, random_state=RANDOM_STATE),
            "grid": {'clf__hidden_layer_sizes': [(50,), (50, 25)], 'clf__max_iter': [40, 60]},
            "plot_params": ('param_clf__hidden_layer_sizes', 'param_clf__max_iter')
        }
    }

    cv = StratifiedKFold(n_splits=CV_SPLITS, shuffle=True, random_state=RANDOM_STATE)

    best_scores = []
    os.makedirs(MODELS_DIR, exist_ok=True)
    if le is not None:
        joblib.dump(le, os.path.join(MODELS_DIR, f"label_encoder_{task_type}.pkl"))

    for name, config in candidates.items():
        print(f"\n--> Optimizando {name}...")

        # Scaler inside pipeline prevents data leakage: each CV fold fits the scaler
        # only on the training partition, never on the validation partition.
        pipe = ImbPipeline([
            ('scaler', RobustScaler()),
            ('smote', SMOTE(sampling_strategy=SMOTE_STRATEGY, random_state=RANDOM_STATE, k_neighbors=4)),
            ('under', RandomUnderSampler(sampling_strategy=UNDER_STRATEGY, random_state=RANDOM_STATE)),
            ('clf', config["model"])
        ])

        grid = GridSearchCV(pipe, config["grid"], cv=cv, scoring='f1_macro', n_jobs=-1, verbose=1)
        grid.fit(X_train, y_train)

        print(f"    Mejor F1-Macro: {grid.best_score_:.4f}")
        print(f"    Mejores params: {grid.best_params_}")

        plot_grid_heatmap(grid.cv_results_, name, task_type, config["plot_params"][0], config["plot_params"][1])

        # Extract scaler and classifier from the best pipeline (refitted on full training set)
        best_scaler = grid.best_estimator_.named_steps['scaler']
        best_clf = grid.best_estimator_.named_steps['clf']
        joblib.dump(best_scaler, os.path.join(MODELS_DIR, f"scaler_{name}_{task_type}.pkl"))
        joblib.dump(best_clf, os.path.join(MODELS_DIR, f"{name}_best_{task_type}.pkl"))

        best_scores.append({"Model": name, "Best_CV_F1": grid.best_score_})

    df_res = pd.DataFrame(best_scores).sort_values(by="Best_CV_F1", ascending=False)
    print(f"\nResumen del Torneo ({task_type}):\n", df_res.to_string(index=False))
    os.makedirs(REPORTS_DIR := "./Results/reports", exist_ok=True)
    df_res.to_csv(os.path.join(REPORTS_DIR, f"tuning_results_{task_type}.csv"), index=False)

if __name__ == "__main__":
    run_tuning_arena("binary")
    run_tuning_arena("multi")
    print("\n>>> Módulo 3 completado. Modelos óptimos listos para evaluación final.")