"""
data_preparation.py  –  CIC-IDS2017  |  Preparación de Datos (Sniffer-Native)
========================================================================
Filtra y estructura los datos basándose exclusivamente en variables de Capa 4
extraíbles en tiempo real por un sniffer perimetral.
"""

import os
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
from sklearn.model_selection import train_test_split

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN GLOBAL
# ──────────────────────────────────────────────────────────────────────────────
RAW_DATA_DIR   = "./DataRaw"
CLEAN_DATA_DIR = "./DataClean"
PLOTS_DIR      = "./Results/plots"
RANDOM_STATE   = 42
TEST_SIZE      = 0.15
USE_LOG_SCALE  = True

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
CLASSES_TO_DROP = ["Infiltration", "Heartbleed"]
MIN_SAMPLES = 100

L4_FEATURES = [
    "Destination Port", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", 
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", 
    "CWE Flag Count", "ECE Flag Count", "Label"
]

sns.set_theme(style="whitegrid", palette="muted")

def load_and_clean_l4(path_to_csvs: str) -> pd.DataFrame:
    print(">>> [1/4] Cargando datos y aplicando filtro metodológico de Sniffer L4...")
    all_files = glob.glob(os.path.join(path_to_csvs, "*.csv"))
    if not all_files:
        raise FileNotFoundError(f"No se encontraron archivos CSV en la ruta: {path_to_csvs}")

    chunks = []
    for f in all_files:
        df_tmp = pd.read_csv(f, low_memory=False)
        df_tmp.columns = df_tmp.columns.str.strip()
        cols_to_keep = [c for c in L4_FEATURES if c in df_tmp.columns]
        chunks.append(df_tmp[cols_to_keep])
        
    df = pd.concat(chunks, ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    df["Label"] = df["Label"].str.strip()
    df = df[~df["Label"].isin(CLASSES_TO_DROP)].copy()

    web_mask = df["Label"].str.contains("Web Attack", case=False, na=False)
    df.loc[web_mask, "Label"] = "Web_Attack"

    class_counts = df["Label"].value_counts()
    rare = class_counts[class_counts < MIN_SAMPLES].index.tolist()
    if rare:
        df = df[~df["Label"].isin(rare)].copy()

    print(f"    Registros viables capturados: {len(df):,}")
    return df

def encode_ports(df: pd.DataFrame) -> pd.DataFrame:
    port_col = "Destination Port"
    if port_col not in df.columns:
        return df
    
    port = df[port_col].astype(int)
    for p in COMMON_PORTS:
        df[f"Port_{p}"] = (port == p).astype(np.int8)

    df["Port_WellKnown"]  = (port <= 1023).astype(np.int8)
    df["Port_Registered"] = ((port > 1023) & (port <= 49151)).astype(np.int8)
    df["Port_Dynamic"]    = (port > 49151).astype(np.int8)
    
    df.drop(columns=[port_col], inplace=True)
    return df

def plot_class_distribution(df: pd.DataFrame, use_log: bool = USE_LOG_SCALE):
    os.makedirs(PLOTS_DIR, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("Distribución del Tráfico Capturado por el Sniffer L4", fontsize=15, fontweight="bold", y=1.01)

    bin_y = df["Label"].apply(lambda x: "BENIGN" if x == "BENIGN" else "Ataque")
    bin_counts = bin_y.value_counts().sort_index()
    
    # Gráfico Binario
    colors_bin = sns.color_palette("Blues_d", n_colors=len(bin_counts))
    bars1 = axes[0].barh(bin_counts.index, bin_counts.values, color=colors_bin, edgecolor="white")
    axes[0].set_title("Tráfico Perimetral (Binario)", fontweight="bold")
    if use_log: axes[0].set_xscale("log")

    df_multi = df[df["Label"] != "BENIGN"]
    mul_counts = df_multi["Label"].value_counts().sort_values(ascending=True)
    
    # Gráfico Multi
    colors_mul = sns.color_palette("Oranges_d", n_colors=len(mul_counts))
    bars2 = axes[1].barh(mul_counts.index, mul_counts.values, color=colors_mul, edgecolor="white")
    axes[1].set_title("Focos de Amenaza (Multiclase)", fontweight="bold")
    if use_log: axes[1].set_xscale("log")

    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "sniffer_class_distribution.png"), dpi=200, bbox_inches="tight")
    plt.close()

def split_and_export(df: pd.DataFrame):
    print(">>> [2/4] Particionando y exportando matrices simétricas con token de auditoría...")
    df_train, df_test = train_test_split(df, test_size=TEST_SIZE, stratify=df["Label"], random_state=RANDOM_STATE)

    for task_type in ["binary", "multi"]:
        output_dir = os.path.join(CLEAN_DATA_DIR, task_type)
        os.makedirs(output_dir, exist_ok=True)

        if task_type == "binary":
            tr_task, te_task = df_train.copy(), df_test.copy()
            tr_task["Original_Label"] = tr_task["Label"]
            te_task["Original_Label"] = te_task["Label"]
            tr_task["Label"] = tr_task["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
            te_task["Label"] = te_task["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
        else:
            tr_task = df_train[df_train["Label"] != "BENIGN"].copy()
            te_task = df_test[df_test["Label"] != "BENIGN"].copy()
            tr_task["Original_Label"] = tr_task["Label"]
            te_task["Original_Label"] = te_task["Label"]

        tr_task.drop(columns=["Label"]).to_csv(os.path.join(output_dir, f"{task_type}_X_train.csv"), index=False)
        tr_task["Label"].to_csv(os.path.join(output_dir, f"{task_type}_y_train.csv"), index=False)
        te_task.drop(columns=["Label"]).to_csv(os.path.join(output_dir, f"{task_type}_X_test.csv"), index=False)
        te_task["Label"].to_csv(os.path.join(output_dir, f"{task_type}_y_test.csv"), index=False)

if __name__ == "__main__":
    df_raw = load_and_clean_l4(RAW_DATA_DIR)
    plot_class_distribution(df_raw)
    df_ready = encode_ports(df_raw)
    split_and_export(df_ready)
    print(">>> Módulo 1 completado.")