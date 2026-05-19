"""
train_and_compare.py  –  CIC-IDS2017  |  Entrenamiento y Evaluación
====================================================================
Cubre los puntos 7-11 del pipeline:
  7.  Cross-validation (StratifiedKFold) para MLP, Random Forest y XGBoost
  8.  En cada fold: SMOTE + undersampling sobre el segmento de ENTRENAMIENTO
  9.  Early stopping para XGBoost (eval_set=val fold) y MLP (built-in)
  10. Matrices de confusión (absoluta + normalizada) sobre el Test Set
  11. Métricas completas por modelo registradas desde el Test Set
"""

import os
import time
import json
import warnings
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
from collections import Counter
from datetime import datetime

from sklearn.model_selection   import StratifiedKFold
from sklearn.ensemble          import RandomForestClassifier
from sklearn.neural_network    import MLPClassifier
from sklearn.preprocessing     import LabelEncoder, RobustScaler
from sklearn.metrics           import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, matthews_corrcoef,
    roc_auc_score, classification_report
)
from xgboost import XGBClassifier
from imblearn.under_sampling   import RandomUnderSampler
from imblearn.over_sampling    import SMOTE
from imblearn.pipeline         import Pipeline as ImbPipeline
from feature_schema import save_feature_columns, CORE_FEATURES

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN GLOBAL
# ──────────────────────────────────────────────────────────────────────────────
K_FOLDS      = 5
RANDOM_STATE = 42

DATA_DIR     = "./DataClean"
MODELS_DIR   = "./Models"
RESULTS_DIR  = "./Results"
PLOTS_DIR    = os.path.join(RESULTS_DIR, "plots")

# Umbrales de balanceo para el caso multiclase
MULTI_MAX_SAMPLES = 50_000   # undersampling: clases con más de N muestras
MULTI_MIN_SAMPLES = 10_000   # oversampling:  clases con menos de N muestras
SMOTE_K_NEIGHBORS = 3

sns.set_theme(style="whitegrid", palette="muted")


# ──────────────────────────────────────────────────────────────────────────────
# FÁBRICA DE MODELOS
# ──────────────────────────────────────────────────────────────────────────────
def get_model(name: str, n_classes: int = 2, use_early_stopping: bool = True):
    """
    Devuelve una instancia fresca del modelo indicado.

    - RandomForest: n_estimators=200, sin early stopping nativo.
    - XGBoost: 1000 árboles con early stopping vía eval_set.
    - MLP: early stopping interno con fracción de validación.
    """
    if name == "RandomForest":
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_leaf=2,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )

    elif name == "XGBoost":
        objective = "binary:logistic" if n_classes == 2 else "multi:softprob"
        eval_metric = "logloss" if n_classes == 2 else "mlogloss"
        params = dict(
            n_estimators=1000,
            learning_rate=0.05,
            max_depth=6,
            subsample=0.8,
            colsample_bytree=0.8,
            objective=objective,
            eval_metric=eval_metric,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            use_label_encoder=False,
        )
        if use_early_stopping:
            params["early_stopping_rounds"] = 20
        return XGBClassifier(**params)

    elif name == "MLP":
        # Early stopping built-in: validation_fraction + n_iter_no_change
        return MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation="relu",
            max_iter=500,
            early_stopping=True,         # [9] early stopping sobre fracción interna
            validation_fraction=0.1,
            n_iter_no_change=20,
            learning_rate_init=1e-3,
            batch_size=256,
            random_state=RANDOM_STATE,
        )

    else:
        raise ValueError(f"Modelo '{name}' no reconocido.")


# ──────────────────────────────────────────────────────────────────────────────
# BALANCEO: SMOTE + UNDERSAMPLING  (Punto 8)
# ──────────────────────────────────────────────────────────────────────────────
def build_balancer(task_type: str, y_train: np.ndarray):
    """
    Construye un pipeline de balanceo adaptativo para el segmento de
    entrenamiento de cada fold.

    Binario:
        Solo undersampling de la clase mayoritaria (BENIGN es ~ 80 % del set).

    Multiclase:
        Undersampling de clases por encima de MULTI_MAX_SAMPLES +
        Oversampling (SMOTE) de clases por debajo de MULTI_MIN_SAMPLES.
    """
    steps = []
    counts = Counter(y_train)

    if task_type == "binary":
        steps.append(("under", RandomUnderSampler(
            sampling_strategy="majority",
            random_state=RANDOM_STATE
        )))

    else:  # multiclase
        under_strategy = {k: MULTI_MAX_SAMPLES
                          for k, v in counts.items() if v > MULTI_MAX_SAMPLES}
        over_strategy  = {k: MULTI_MIN_SAMPLES
                          for k, v in counts.items()
                          if v < MULTI_MIN_SAMPLES and v >= SMOTE_K_NEIGHBORS + 1}

        if under_strategy:
            steps.append(("under", RandomUnderSampler(
                sampling_strategy=under_strategy,
                random_state=RANDOM_STATE
            )))
        if over_strategy:
            steps.append(("smote", SMOTE(
                sampling_strategy=over_strategy,
                k_neighbors=SMOTE_K_NEIGHBORS,
                random_state=RANDOM_STATE
            )))

    if not steps:
        return None
    return ImbPipeline(steps=steps)


# ──────────────────────────────────────────────────────────────────────────────
# MÉTRICAS  (Punto 11)
# ──────────────────────────────────────────────────────────────────────────────
def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray,
                    y_prob: np.ndarray, task_type: str,
                    le: LabelEncoder = None) -> dict:
    """
    Calcula un conjunto completo de métricas sobre el conjunto de test.

    Retorna un diccionario con:
        Accuracy, Precision, Recall, F1 (weighted), MCC,
        ROC-AUC (OvR para multiclase), Train_Time
    """
    avg = "binary" if task_type == "binary" else "weighted"
    zero_div = 0

    metrics = {
        "Accuracy"  : accuracy_score(y_true, y_pred),
        "Precision" : precision_score(y_true, y_pred, average=avg,
                                      zero_division=zero_div),
        "Recall"    : recall_score(y_true, y_pred, average=avg,
                                   zero_division=zero_div),
        "F1"        : f1_score(y_true, y_pred, average=avg,
                               zero_division=zero_div),
        "MCC"       : matthews_corrcoef(y_true, y_pred),
    }

    # ROC-AUC (requiere probabilidades)
    try:
        if task_type == "binary":
            metrics["ROC_AUC"] = roc_auc_score(y_true, y_prob[:, 1])
        else:
            metrics["ROC_AUC"] = roc_auc_score(
                y_true, y_prob,
                multi_class="ovr",
                average="weighted"
            )
    except Exception:
        metrics["ROC_AUC"] = float("nan")

    return metrics


# ──────────────────────────────────────────────────────────────────────────────
# VISUALIZACIONES
# ──────────────────────────────────────────────────────────────────────────────
def plot_confusion_matrix(y_true, y_pred, class_names, title, save_path):
    """
    Punto 10: Matriz de confusión doble (absoluta + normalizada por recall).
    """
    cm = confusion_matrix(y_true, y_pred)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)

    n = len(class_names)
    cell_size = max(0.7, min(1.2, 8 / n))
    figsize = (cell_size * n * 2 + 3, cell_size * n + 2)

    fig, axes = plt.subplots(1, 2, figsize=figsize)

    kw = dict(xticklabels=class_names, yticklabels=class_names, cbar=False)

    sns.heatmap(cm,      annot=True, fmt="d",    cmap="Blues",   ax=axes[0], **kw)
    axes[0].set_title("Conteo Absoluto", fontsize=12, fontweight="bold")
    axes[0].set_xlabel("Predicho"); axes[0].set_ylabel("Real")

    sns.heatmap(cm_norm, annot=True, fmt=".2f",  cmap="Oranges", ax=axes[1], **kw)
    axes[1].set_title("Normalizada (Recall por clase)", fontsize=12, fontweight="bold")
    axes[1].set_xlabel("Predicho"); axes[1].set_ylabel("Real")

    for ax in axes:
        ax.set_xticklabels(ax.get_xticklabels(), rotation=40, ha="right", fontsize=8)
        ax.set_yticklabels(ax.get_yticklabels(), rotation=0,  fontsize=8)

    plt.suptitle(title, fontsize=14, fontweight="bold")
    plt.tight_layout()
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close()


def plot_cv_variance(df_cv: pd.DataFrame, task_type: str):
    """
    Punto 7: Boxplot del F1-Score a través de los K folds por modelo.
    """
    save_path = os.path.join(RESULTS_DIR, f"cv_variance_{task_type}.png")
    fig, ax = plt.subplots(figsize=(9, 5))

    sns.boxplot(
        data=df_cv, x="Model", y="F1",
        hue="Model", palette="Set2", legend=False, ax=ax,
        linewidth=1.5, flierprops=dict(marker="o", markersize=5, alpha=0.5)
    )
    # Línea de mediana de cada modelo
    for i, model in enumerate(df_cv["Model"].unique()):
        med = df_cv.loc[df_cv["Model"] == model, "F1"].median()
        ax.text(i, med + 0.002, f"{med:.4f}", ha="center", va="bottom",
                fontsize=9, color="black", fontweight="bold")

    ax.set_title(f"Varianza F1-Score — Cross-Validation ({K_FOLDS} Folds) "
                 f"| {task_type.upper()}", fontsize=13, fontweight="bold")
    ax.set_xlabel(""); ax.set_ylabel("F1-Score")
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.4f"))
    ax.grid(axis="y", linestyle="--", alpha=0.6)
    ax.spines[["top", "right"]].set_visible(False)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"    CV variance plot guardado: {save_path}")


def plot_metrics_comparison(df_results: pd.DataFrame, task_type: str):
    """
    Barplot comparativo de todas las métricas de test para los modelos.
    """
    metrics_cols = ["Accuracy", "Precision", "Recall", "F1", "MCC", "ROC_AUC"]
    df_melt = df_results[["Model"] + metrics_cols].melt(
        id_vars="Model", var_name="Metric", value_name="Value"
    )

    fig, ax = plt.subplots(figsize=(12, 5))
    sns.barplot(data=df_melt, x="Metric", y="Value", hue="Model",
                palette="Set1", ax=ax, edgecolor="white")

    ax.set_title(f"Comparativa de Métricas en Test Set — {task_type.upper()}",
                 fontsize=13, fontweight="bold")
    ax.set_ylim(0, 1.08)
    ax.set_xlabel(""); ax.set_ylabel("Valor")
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.3f"))

    for container in ax.containers:
        ax.bar_label(container, fmt="%.3f", fontsize=7.5, padding=2)

    ax.legend(title="Modelo", bbox_to_anchor=(1, 1), loc="upper left")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)

    save_path = os.path.join(RESULTS_DIR, f"metrics_comparison_{task_type}.png")
    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"    Metrics comparison guardado: {save_path}")


# ──────────────────────────────────────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ──────────────────────────────────────────────────────────────────────────────
def run_pipeline(task_type: str) -> pd.DataFrame:
    """
    Ejecuta el pipeline completo para 'binary' o 'multi':
      1. Carga datos
      2. Cross-validation con balanceo por fold (puntos 7, 8, 9)
      3. Entrenamiento del modelo final sobre todo el train set
      4. Evaluación sobre el test set (puntos 10, 11)
    """
    print(f"\n{'='*60}")
    print(f"  PIPELINE: {task_type.upper()}")
    print(f"{'='*60}")

    # ── Directorios de salida
    models_task = os.path.join(MODELS_DIR, task_type)
    plots_task  = os.path.join(PLOTS_DIR, task_type)
    os.makedirs(models_task, exist_ok=True)
    os.makedirs(plots_task,  exist_ok=True)

    # ── Carga de datos
    base = os.path.join(DATA_DIR, task_type)
    X_train_full = pd.read_csv(f"{base}/{task_type}_X_train.csv")
    y_train = pd.read_csv(f"{base}/{task_type}_y_train.csv").values.ravel()
    X_test_full  = pd.read_csv(f"{base}/{task_type}_X_test.csv")
    y_test  = pd.read_csv(f"{base}/{task_type}_y_test.csv").values.ravel()

    # ── Seleccionar solo CORE_FEATURES (14 features byte-count-independent)
    X_train = X_train_full[[c for c in CORE_FEATURES if c in X_train_full.columns]]
    X_test  = X_test_full[[c for c in CORE_FEATURES if c in X_test_full.columns]]
    print(f"  Características originales: {X_train_full.shape[1]}")
    print(f"  Core features seleccionadas: {X_train.shape[1]} ({', '.join(CORE_FEATURES[:3])}...)")

    # ── Encoding de etiquetas para multiclase (XGBoost requiere enteros)
    le = None
    if task_type == "multi":
        le = LabelEncoder()
        y_train = le.fit_transform(y_train)
        y_test  = le.transform(y_test)
        joblib.dump(le, os.path.join(models_task, "label_encoder.pkl"))
        print(f"  Clases ({len(le.classes_)}): {list(le.classes_)}")

    n_classes    = len(np.unique(y_train))
    class_names  = le.classes_.tolist() if le else ["BENIGN", "Ataque"]
    avg_method   = "binary" if task_type == "binary" else "weighted"
    model_names  = ["RandomForest", "XGBoost", "MLP"]

    # ──────────────────────────────────────────────────────────────────────────
    # ETAPA 1: CROSS-VALIDATION  (Puntos 7, 8, 9)
    # ──────────────────────────────────────────────────────────────────────────
    print(f"\n>>> Cross-Validation ({K_FOLDS} folds)...")
    cv_records = []
    skf = StratifiedKFold(n_splits=K_FOLDS, shuffle=True, random_state=RANDOM_STATE)

    for name in model_names:
        print(f"\n  ● Modelo: {name}")
        fold_times = []

        for fold, (tr_idx, val_idx) in enumerate(
                skf.split(X_train, y_train), start=1):

            X_tr  = X_train.iloc[tr_idx].values
            X_val = X_train.iloc[val_idx].values
            y_tr  = y_train[tr_idx]
            y_val = y_train[val_idx]

            # [8] Escalar ANTES del balanceo (ajuste solo sobre X_tr)
            scaler = RobustScaler()
            X_tr  = scaler.fit_transform(X_tr)
            X_val = scaler.transform(X_val)

            # [8] SMOTE + undersampling solo sobre la parte de entrenamiento
            balancer = build_balancer(task_type, y_tr)
            if balancer:
                X_tr, y_tr = balancer.fit_resample(X_tr, y_tr)

            # Instancia fresca del modelo
            model = get_model(name, n_classes=n_classes, use_early_stopping=True)

            t0 = time.time()
            # [9] Early stopping: XGBoost usa el val fold como eval_set
            if name == "XGBoost":
                model.fit(
                    X_tr, y_tr,
                    eval_set=[(X_val, y_val)],
                    verbose=False
                )
            else:
                # MLP tiene early_stopping=True internamente
                model.fit(X_tr, y_tr)
            fold_times.append(time.time() - t0)

            f1 = f1_score(y_val, model.predict(X_val),
                          average=avg_method, zero_division=0)
            cv_records.append({"Model": name, "Fold": fold, "F1": f1})
            print(f"    Fold {fold}/{K_FOLDS} — F1 val: {f1:.4f}  "
                  f"({fold_times[-1]:.1f}s)")

        mean_f1 = np.mean([r["F1"] for r in cv_records if r["Model"] == name])
        std_f1  = np.std( [r["F1"] for r in cv_records if r["Model"] == name])
        print(f"    → F1 promedio: {mean_f1:.4f} ± {std_f1:.4f}")

    df_cv = pd.DataFrame(cv_records)
    plot_cv_variance(df_cv, task_type)
    df_cv.to_csv(os.path.join(RESULTS_DIR, f"cv_folds_{task_type}.csv"), index=False)

    # ──────────────────────────────────────────────────────────────────────────
    # ETAPA 2: ENTRENAMIENTO FINAL + EVALUACIÓN EN TEST  (Puntos 10, 11)
    # ──────────────────────────────────────────────────────────────────────────
    print(f"\n>>> Entrenamiento final y evaluación en Test Set...")
    final_results = []

    for name in model_names:
        print(f"\n  ● Modelo: {name}")

        # Escalar con TODO el train set
        scaler_final = RobustScaler()
        X_tr_sc  = scaler_final.fit_transform(X_train.values)
        X_te_sc  = scaler_final.transform(X_test.values)

        # Balanceo sobre todo el train
        balancer_final = build_balancer(task_type, y_train)
        if balancer_final:
            X_bal, y_bal = balancer_final.fit_resample(X_tr_sc, y_train)
        else:
            X_bal, y_bal = X_tr_sc, y_train

        # Modelo final SIN early stopping (se usa todo el train balanceado)
        model_final = get_model(name, n_classes=n_classes, use_early_stopping=False)

        t0 = time.time()
        model_final.fit(X_bal, y_bal)
        train_time = time.time() - t0

        # Predicción en test
        t1 = time.time()
        y_pred = model_final.predict(X_te_sc)
        infer_time = time.time() - t1

        # Probabilidades (para ROC-AUC)
        try:
            y_prob = model_final.predict_proba(X_te_sc)
        except Exception:
            y_prob = np.zeros((len(y_test), n_classes))

        # [11] Métricas completas
        met = compute_metrics(y_test, y_pred, y_prob, task_type, le)
        met.update({
            "Model"      : name,
            "Task"       : task_type,
            "Train_Time" : round(train_time, 2),
            "Infer_Time" : round(infer_time, 4),
        })
        final_results.append(met)

        print(f"    Accuracy : {met['Accuracy']:.4f}")
        print(f"    Precision: {met['Precision']:.4f}")
        print(f"    Recall   : {met['Recall']:.4f}")
        print(f"    F1       : {met['F1']:.4f}")
        print(f"    MCC      : {met['MCC']:.4f}")
        print(f"    ROC-AUC  : {met['ROC_AUC']:.4f}")
        print(f"    Tiempo entreno: {train_time:.1f}s  |  Inferencia: {infer_time:.3f}s")

        # [10] Matriz de confusión sobre test
        cm_path  = os.path.join(plots_task, f"cm_{name}.png")
        cm_title = f"{name} — Test Set ({task_type.upper()})"
        plot_confusion_matrix(y_test, y_pred, class_names, cm_title, cm_path)
        print(f"    CM guardada: {cm_path}")

        # Reporte por clase
        report_path = os.path.join(RESULTS_DIR, f"report_{task_type}_{name}.txt")
        target_names = class_names if le is None else le.classes_.tolist()
        report = classification_report(
            y_test, y_pred,
            target_names=target_names,
            zero_division=0
        )
        with open(report_path, "w") as fh:
            fh.write(f"Modelo: {name}  |  Task: {task_type}\n")
            fh.write("=" * 60 + "\n")
            fh.write(report)
        print(f"    Report guardado: {report_path}")

        # Guardar artefactos
        joblib.dump(model_final,  os.path.join(models_task, f"{name}_final.pkl"))
        joblib.dump(scaler_final, os.path.join(models_task, f"scaler_{name}.pkl"))

    df_results = pd.DataFrame(final_results)
    plot_metrics_comparison(df_results, task_type)

    # ──────────────────────────────────────────────────────────────────────────
    # METADATA EXPORT: feature_columns.json, best_model_name.txt, metadata_*.json
    # ──────────────────────────────────────────────────────────────────────────
    # 1. Save feature columns for live inference
    feature_cols = X_train.columns.tolist()
    save_feature_columns(feature_cols, os.path.join(models_task, "feature_columns.json"))
    print(f"\n  ✓ feature_columns.json guardado ({len(feature_cols)} features)")

    # 2. Select best model: highest F1 (or F1 Weighted for multi), MCC as tiebreaker
    metric_col = "F1" if task_type == "binary" else "F1"
    best_row = df_results.sort_values([metric_col, "MCC"], ascending=False).iloc[0]
    best_name = best_row["Model"]
    with open(os.path.join(models_task, "best_model_name.txt"), "w") as f:
        f.write(best_name)
    print(f"  ✓ best_model_name.txt guardado: {best_name} (F1={best_row[metric_col]:.4f})")

    # 3. Save per-model metadata
    for idx, row in df_results.iterrows():
        model_name = row["Model"]
        metadata = {
            "task_type": task_type,
            "model_name": model_name,
            "feature_columns": feature_cols,
            "scaler_path": f"Models/{task_type}/scaler_{model_name}.pkl",
            "model_path": f"Models/{task_type}/{model_name}_final.pkl",
            "label_encoder_path": f"Models/{task_type}/label_encoder.pkl" if task_type == "multi" else None,
            "metrics": row.to_dict(),
            "trained_at": datetime.now().isoformat()
        }
        metadata_path = os.path.join(models_task, f"metadata_{model_name}.json")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        if model_name == best_name:
            with open(os.path.join(models_task, "model_metadata.json"), "w") as f:
                json.dump(metadata, f, indent=2)
    print(f"  ✓ metadata_*.json guardados ({len(df_results)} modelos)")

    return df_results


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    for d in [MODELS_DIR, RESULTS_DIR, PLOTS_DIR]:
        os.makedirs(d, exist_ok=True)

    print("=" * 60)
    print("   CIC-IDS2017 — Pipeline de Entrenamiento y Evaluación")
    print("=" * 60)

    results = []
    for task in ["binary", "multi"]:
        df_r = run_pipeline(task)
        results.append(df_r)

    # Reporte global consolidado
    df_final = pd.concat(results, ignore_index=True)
    cols_order = ["Task", "Model", "Accuracy", "Precision", "Recall",
                  "F1", "MCC", "ROC_AUC", "Train_Time", "Infer_Time"]
    df_final = df_final[[c for c in cols_order if c in df_final.columns]]
    report_path = os.path.join(RESULTS_DIR, "final_performance_report.csv")
    df_final.to_csv(report_path, index=False)

    print("\n" + "=" * 60)
    print("   Pipeline finalizado.")
    print(f"   Reporte global: {report_path}")
    print("=" * 60)
    print("\n" + df_final.to_string(index=False))
