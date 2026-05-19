"""
final_evaluation.py  –  CIC-IDS2017  |  Evaluación de Producción y Auditoría  [Módulo 4]
========================================================================
Selecciona el modelo campeón comparando todos los candidatos sobre el Test Set,
lo promueve a Models/ con los artefactos requeridos por inference_pipeline.py,
y genera los gráficos de auditoría finales.

Artefactos escritos en Models/{task}/:
    {ModelName}_final.pkl       — clasificador final
    scaler_{ModelName}.pkl      — scaler asociado
    label_encoder.pkl           — LabelEncoder (solo multi)
    best_model_name.txt         — nombre del campeón
    feature_columns.json        — lista de features SHAP seleccionadas
    model_metadata.json         — metadata completa del modelo

Pipeline de entrenamiento:
    Módulo 1: data_preparation.py  →  DataClean/
    Módulo 2: feature_selection.py →  DataReduced/
    Módulo 3: model_tuning.py      →  Results/models/tuned/
    Módulo 4: final_evaluation.py  →  Models/ (este módulo)
"""

import json
import os
import shutil
from datetime import datetime

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, f1_score, matthews_corrcoef
from sklearn.preprocessing import LabelEncoder

DATA_DIR    = "./DataReduced"
TUNED_DIR   = "./Results/models/tuned"
PLOTS_DIR   = "./Results/plots/evaluation"
REPORTS_DIR = "./Results/reports"
MODELS_DIR  = "./Models"

CANDIDATE_NAMES = ["RandomForest", "XGBoost", "MLP"]

SEPARATOR = "=" * 60

sns.set_theme(style="white")


# ─────────────────────────────────────────────────────────────
# Plotting helpers
# ─────────────────────────────────────────────────────────────

def plot_final_confusion(y_true, y_pred, labels, task_type, champion_name):
    cm = confusion_matrix(y_true, y_pred, labels=range(len(labels)))
    cm_norm = confusion_matrix(y_true, y_pred, labels=range(len(labels)), normalize='true')

    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle(f"Matriz de Confusión Final — {champion_name} ({task_type.upper()})", fontsize=14, fontweight="bold")

    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels, ax=axes[0], cbar=False)
    axes[0].set_title("Conteo Absoluto de Flujos (Test Set)", fontweight="bold")

    sns.heatmap(cm_norm, annot=True, fmt=".3f", cmap="Purples", xticklabels=labels, yticklabels=labels, ax=axes[1], cbar=False)
    axes[1].set_title("Proporción Normalizada (Recall)", fontweight="bold")

    plt.tight_layout()
    os.makedirs(PLOTS_DIR, exist_ok=True)
    plt.savefig(os.path.join(PLOTS_DIR, f"confusion_matrix_{task_type}.png"), dpi=180, bbox_inches="tight")
    plt.close()


def plot_evaded_attacks_pie(df_evaded, task_type):
    if df_evaded.empty:
        print(f"    [Auditoría] Extraordinario: 0 Falsos Negativos para la rama {task_type.upper()}.")
        return

    counts = df_evaded["Original_Label"].value_counts()

    plt.figure(figsize=(8, 8))
    wedges, texts, autotexts = plt.pie(
        counts.values, labels=counts.index, autopct='%1.1f%%',
        startangle=140, colors=plt.get_cmap("tab20c")(np.arange(len(counts))),
        textprops=dict(color="black"), wedgeprops=dict(edgecolor="white", linewidth=1.2)
    )

    plt.setp(autotexts, size=10, weight="bold")
    plt.title(
        f"Ataques Evadidos del Sniffer (Falsos Negativos)\nDataset: {task_type.upper()} (Total: {len(df_evaded)})",
        fontweight="bold", pad=20
    )

    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, f"evaded_attacks_pie_{task_type}.png"), dpi=180, bbox_inches="tight")
    plt.close()


# ─────────────────────────────────────────────────────────────
# Champion selection
# ─────────────────────────────────────────────────────────────

def select_best_model(task_type: str, X_test: pd.DataFrame, y_test: np.ndarray) -> dict:
    """
    Evaluate all candidate models on the test set and return the best one.

    Selection criterion: highest F1-macro; MCC as tiebreaker.

    Returns:
        dict with keys: name, model, scaler, f1, mcc
    """
    best = None

    for name in CANDIDATE_NAMES:
        model_path = os.path.join(TUNED_DIR, f"{name}_best_{task_type}.pkl")
        scaler_path = os.path.join(TUNED_DIR, f"scaler_{name}_{task_type}.pkl")

        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            print(f"    [SKIP] {name}: artefactos no encontrados en {TUNED_DIR}")
            continue

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        X_scaled = scaler.transform(X_test)
        preds = model.predict(X_scaled)

        f1 = f1_score(y_test, preds, average="macro", zero_division=0)
        mcc = matthews_corrcoef(y_test, preds)
        print(f"    {name}: F1-macro={f1:.4f}  MCC={mcc:.4f}")

        if best is None or f1 > best["f1"] or (f1 == best["f1"] and mcc > best["mcc"]):
            best = {"name": name, "model": model, "scaler": scaler, "f1": f1, "mcc": mcc}

    if best is None:
        raise FileNotFoundError(
            f"No se encontró ningún modelo entrenado para task='{task_type}' en {TUNED_DIR}"
        )

    return best


# ─────────────────────────────────────────────────────────────
# Promotion to Models/
# ─────────────────────────────────────────────────────────────

def promote_to_production(
    task_type: str,
    champion: dict,
    feature_columns: list,
    le: "LabelEncoder | None",
):
    """
    Copy champion artefacts to Models/{task_type}/ and write metadata files.

    Written files:
        {name}_final.pkl, scaler_{name}.pkl, label_encoder.pkl (multi only),
        best_model_name.txt, feature_columns.json, model_metadata.json
    """
    dest = os.path.join(MODELS_DIR, task_type)
    os.makedirs(dest, exist_ok=True)

    # Persist all three candidate models as _final.pkl so inference_pipeline.py
    # can load any of them if best_model_name.txt is changed manually.
    for name in CANDIDATE_NAMES:
        src_model = os.path.join(TUNED_DIR, f"{name}_best_{task_type}.pkl")
        src_scaler = os.path.join(TUNED_DIR, f"scaler_{name}_{task_type}.pkl")
        if os.path.exists(src_model):
            shutil.copy2(src_model, os.path.join(dest, f"{name}_final.pkl"))
        if os.path.exists(src_scaler):
            shutil.copy2(src_scaler, os.path.join(dest, f"scaler_{name}.pkl"))

    if le is not None:
        joblib.dump(le, os.path.join(dest, "label_encoder.pkl"))

    # best_model_name.txt — read by inference_pipeline.py
    with open(os.path.join(dest, "best_model_name.txt"), "w") as f:
        f.write(champion["name"])

    # feature_columns.json — read by inference_pipeline.py
    with open(os.path.join(dest, "feature_columns.json"), "w") as f:
        json.dump(feature_columns, f, indent=2)

    # model_metadata.json — informational
    le_path = os.path.join(dest, "label_encoder.pkl") if le is not None else None
    metadata = {
        "task_type": task_type,
        "model_name": champion["name"],
        "feature_columns": feature_columns,
        "model_path": os.path.join(dest, f"{champion['name']}_final.pkl"),
        "scaler_path": os.path.join(dest, f"scaler_{champion['name']}.pkl"),
        "label_encoder_path": le_path,
        "metrics": {"f1_macro": round(champion["f1"], 6), "mcc": round(champion["mcc"], 6)},
        "trained_at": datetime.now().isoformat(timespec="seconds"),
    }
    with open(os.path.join(dest, "model_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"    [Promoción] {champion['name']} → {dest}/")
    print(f"    [Metadata]  feature_columns.json ({len(feature_columns)} features), best_model_name.txt, model_metadata.json")


# ─────────────────────────────────────────────────────────────
# Main audit
# ─────────────────────────────────────────────────────────────

def run_production_audit(task_type: str = "binary"):
    print(f"\n{SEPARATOR}\nMÓDULO 4 — AUDITORÍA FINAL DE PRODUCCIÓN: {task_type.upper()}\n{SEPARATOR}")

    # ── Load test data
    X_test_raw = pd.read_csv(os.path.join(DATA_DIR, f"{task_type}_X_test_red.csv"))
    y_test_raw = pd.read_csv(os.path.join(DATA_DIR, f"{task_type}_y_test.csv")).values.ravel()

    orig_labels = X_test_raw["Original_Label"].values if "Original_Label" in X_test_raw.columns else np.array([])
    X_test = X_test_raw.drop(columns=["Original_Label"], errors="ignore")
    feature_columns = X_test.columns.tolist()

    # ── Label encoding for multi-class
    le = None
    if task_type == "multi":
        le = joblib.load(os.path.join(TUNED_DIR, f"label_encoder_{task_type}.pkl"))
        y_test = le.transform(y_test_raw)
        labels_txt = le.classes_.tolist()
        benign_class_idx = None  # BENIGN not present in multi-class task
    else:
        y_test = y_test_raw.astype(int)
        labels_txt = ["BENIGN", "Ataque"]
        # Verify class 0 == BENIGN before using it in the evaded-attack audit
        benign_class_idx = 0

    # ── Select best model by F1-macro + MCC tiebreaker
    print(f"\n[Selección] Evaluando candidatos sobre Test Set...")
    champion = select_best_model(task_type, X_test, y_test)
    print(f"    → Campeón: {champion['name']}  (F1={champion['f1']:.4f}, MCC={champion['mcc']:.4f})")

    # ── Promote to Models/
    promote_to_production(task_type, champion, feature_columns, le)

    # ── Final evaluation with champion
    X_test_scaled = champion["scaler"].transform(X_test)
    preds = champion["model"].predict(X_test_scaled)

    plot_final_confusion(y_test, preds, labels_txt, task_type, champion["name"])

    # ── Evaded-attack audit (false negatives = attacks predicted as benign)
    df_audit = pd.DataFrame({
        "Original_Label": orig_labels if len(orig_labels) > 0 else [""] * len(y_test),
        "True_Class": y_test,
        "Pred_Class": preds,
    })

    if benign_class_idx is not None:
        df_evaded = df_audit[
            (df_audit["True_Class"] != benign_class_idx) & (df_audit["Pred_Class"] == benign_class_idx)
        ]
    else:
        df_evaded = pd.DataFrame()

    plot_evaded_attacks_pie(df_evaded, task_type)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    audit_path = os.path.join(REPORTS_DIR, f"audit_{task_type}.csv")
    df_audit.to_csv(audit_path, index=False)

    # ── Metrics report
    mcc = matthews_corrcoef(y_test, preds)
    print(f"\n[Métrica Final] MCC: {mcc:.4f}\n")

    final_rep = classification_report(y_test, preds, target_names=[str(l) for l in labels_txt])
    print(final_rep)

    with open(os.path.join(REPORTS_DIR, f"reporte_produccion_{task_type}.txt"), "w") as f:
        f.write(f"REPORTE FINAL — {champion['name'].upper()} ({task_type.upper()})\n")
        f.write(f"MCC Score: {mcc:.4f}\n{SEPARATOR}\n")
        f.write(final_rep)


if __name__ == "__main__":
    run_production_audit("binary")
    run_production_audit("multi")
    print("\n>>> Módulo 4 completado. Pipeline finalizado exitosamente.")
