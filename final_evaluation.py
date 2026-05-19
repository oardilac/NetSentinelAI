"""
final_evaluation.py  –  CIC-IDS2017  |  Evaluación de Producción y Auditoría
========================================================================
Toma el modelo campeón del GridSearch, lo evalúa contra el Test Set
y genera los gráficos finales (Matriz de confusión y Pastel de Falsos Negativos).
"""

import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, matthews_corrcoef

DATA_DIR    = "./DataReduced"
MODELS_DIR  = "./Results/models/tuned"
PLOTS_DIR   = "./Results/plots/evaluation"
REPORTS_DIR = "./Results/reports"

sns.set_theme(style="white")

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
    plt.title(f"Ataques Evadidos del Sniffer (Falsos Negativos)\nDataset: {task_type.upper()} (Total: {len(df_evaded)})", fontweight="bold", pad=20)
    
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, f"evaded_attacks_pie_{task_type}.png"), dpi=180, bbox_inches="tight")
    plt.close()

def run_production_audit(task_type="binary", champion_model="XGBoost"):
    print(f"\n{'='*60}\nAUDITORIA FINAL DE PRODUCCIÓN: {task_type.upper()} | Campeón: {champion_model}\n{'='*60}")
    
    X_test_raw = pd.read_csv(os.path.join(DATA_DIR, f"{task_type}_X_test_red.csv"))
    y_test_raw = pd.read_csv(os.path.join(DATA_DIR, f"{task_type}_y_test.csv")).values.ravel()

    orig_labels = X_test_raw["Original_Label"].values if "Original_Label" in X_test_raw.columns else []
    X_test = X_test_raw.drop(columns=["Original_Label"], errors="ignore")
    
    scaler = joblib.load(os.path.join(MODELS_DIR, f"scaler_{task_type}.pkl"))
    model  = joblib.load(os.path.join(MODELS_DIR, f"{champion_model}_best_{task_type}.pkl"))
    
    if task_type == "multi":
        le = joblib.load(os.path.join(MODELS_DIR, f"label_encoder_{task_type}.pkl"))
        y_test = le.transform(y_test_raw)
        labels_txt = le.classes_.tolist()
    else:
        y_test = y_test_raw.astype(int)
        labels_txt = ["BENIGN", "Ataque"]

    X_test_scaled = scaler.transform(X_test)
    preds = model.predict(X_test_scaled)
    
    plot_final_confusion(y_test, preds, labels_txt, task_type, champion_model)

    df_audit = pd.DataFrame({"Original_Label": orig_labels, "True_Class": y_test, "Pred_Class": preds})
    df_evaded = df_audit[(df_audit["True_Class"] != 0) & (df_audit["Pred_Class"] == 0)]
    plot_evaded_attacks_pie(df_evaded, task_type)

    mcc = matthews_corrcoef(y_test, preds)
    print(f"\n[Métrica Final] Matthews Correlation Coefficient (MCC): {mcc:.4f}\n")
    
    final_rep = classification_report(y_test, preds, target_names=[str(l) for l in labels_txt])
    print(final_rep)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(os.path.join(REPORTS_DIR, f"reporte_produccion_{task_type}.txt"), "w") as f:
        f.write(f"REPORTE FINAL — {champion_model.upper()} ({task_type.upper()})\n")
        f.write(f"MCC Score: {mcc:.4f}\n{'='*60}\n")
        f.write(final_rep)

if __name__ == "__main__":
    # Configura aquí el nombre del modelo que ganó en el Módulo 3
    run_production_audit("binary", champion_model="XGBoost")
    run_production_audit("multi", champion_model="XGBoost")
    print("\n>>> Módulo 4 completado. Pipeline finalizado exitosamente.")