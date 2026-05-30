"""
01_prep.py - MÓDULO 1: Preparación y Validación de Proporciones Estratificadas
================================================================================
- Divide los conjuntos en Train (85%) y Test (15%).
- Calcula y muestra el porcentaje proporcional exacto de cada ataque en Train vs Test.
"""

import os
import glob
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.model_selection import train_test_split

RAW_DATA_DIR = "./DataRaw"
CLEAN_DATA_DIR = "./DataClean"
PLOTS_DIR = "./Results/plots"

CLASSES_TO_DROP = ["Infiltration", "Heartbleed"]
MIN_SAMPLES = 100
TEST_SIZE = 0.15
RANDOM_STATE = 42

def load_and_clean_l4_strict(path_to_csvs: str) -> pd.DataFrame:
    print(">>> [Módulo 1] Cargando y filtrando datos (Lista Blanca - Sniffer)...")
    all_files = glob.glob(os.path.join(path_to_csvs, "*.csv"))
    if not all_files:
        raise FileNotFoundError(f"No se encontraron archivos CSV en: {path_to_csvs}")

    chunks = [pd.read_csv(f, low_memory=False) for f in all_files]
    df = pd.concat(chunks, ignore_index=True)
    df.columns = df.columns.str.strip()

    real_time_features = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min", 
        "Bwd Packet Length Max", "Bwd Packet Length Min",
        "Flow Packets/s", "Flow Bytes/s",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", 
        "ACK Flag Count", "URG Flag Count", "ECE Flag Count",
        "Down/Up Ratio", "Label"
    ]
    
    df = df[[col for col in real_time_features if col in df.columns]].copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    df["Label"] = df["Label"].str.strip()
    df = df[~df["Label"].isin(CLASSES_TO_DROP)].copy()
    df.loc[df["Label"].str.contains("Web Attack", case=False, na=False), "Label"] = "Web_Attack"

    class_counts = df["Label"].value_counts()
    rare = class_counts[class_counts < MIN_SAMPLES].index.tolist()
    if rare: df = df[~df["Label"].isin(rare)].copy()

    print(f"    Registros totales limpios: {len(df):,} | Variables: {df.shape[1] - 1}")
    return df

def generate_split_and_plot(df: pd.DataFrame, task_type: str):
    print(f">>> [Módulo 1] Procesando particiones para: {task_type.upper()}")
    output_dir = os.path.join(CLEAN_DATA_DIR, task_type)
    os.makedirs(output_dir, exist_ok=True)
    
    if task_type == "binary":
        X = df.drop(columns=["Label"])
        y_bin = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
        y_comb = pd.DataFrame({"binary": y_bin, "original_attack": df["Label"]})
        
        X_train, X_test, y_train_comb, y_test_comb = train_test_split(
            X, y_comb, test_size=TEST_SIZE, stratify=y_comb["original_attack"], random_state=RANDOM_STATE
        )
        
        X_train.to_csv(f"{output_dir}/binary_X_train.csv", index=False)
        X_test.to_csv(f"{output_dir}/binary_X_test.csv", index=False)
        y_train_comb["binary"].to_csv(f"{output_dir}/binary_y_train.csv", index=False)
        y_test_comb["binary"].to_csv(f"{output_dir}/binary_y_test.csv", index=False)
        y_test_comb["original_attack"].to_csv(f"{output_dir}/binary_y_test_attacks.csv", index=False)
        
        df_tr_lbl = pd.DataFrame({"Clase": y_train_comb["binary"].map({0: "BENIGN", 1: "ATAQUE"}), "Split": "Train"})
        df_te_lbl = pd.DataFrame({"Clase": y_test_comb["binary"].map({0: "BENIGN", 1: "ATAQUE"}), "Split": "Test"})
    else:
        df_multi = df[df["Label"] != "BENIGN"].copy()
        X_train, X_test, y_train, y_test = train_test_split(
            df_multi.drop(columns=["Label"]), df_multi["Label"], test_size=TEST_SIZE, stratify=df_multi["Label"], random_state=RANDOM_STATE
        )
        
        X_train.to_csv(f"{output_dir}/multi_X_train.csv", index=False)
        X_test.to_csv(f"{output_dir}/multi_X_test.csv", index=False)
        pd.DataFrame(y_train).to_csv(f"{output_dir}/multi_y_train.csv", index=False)
        pd.DataFrame(y_test).to_csv(f"{output_dir}/multi_y_test.csv", index=False)
        
        df_tr_lbl = pd.DataFrame({"Clase": y_train, "Split": "Train"})
        df_te_lbl = pd.DataFrame({"Clase": y_test, "Split": "Test"})

    # Cálculo de proporciones
    df_counts = pd.concat([df_tr_lbl, df_te_lbl]).groupby(["Clase", "Split"]).size().reset_index(name="Muestras")
    
    total_por_split = df_counts.groupby("Split")["Muestras"].transform("sum")
    df_counts["Proporcion_Porcentaje"] = (df_counts["Muestras"] / total_por_split) * 100
    df_counts["Texto_Grafico"] = df_counts["Proporcion_Porcentaje"].round(1).astype(str) + "%"

    fig = px.bar(
        df_counts, x="Clase", y="Proporcion_Porcentaje", color="Split", barmode="group",
        text="Texto_Grafico", title=f"Distribución Relativa y Simetría de Datos (%) — {task_type.upper()}",
        labels={"Proporcion_Porcentaje": "% del Total del Set", "Clase": "Firma de Red"},
        color_discrete_sequence=px.colors.qualitative.Pastel
    )
    
    fig.update_traces(textposition='outside')
    
    # CORRECCIÓN: ticksuffix dentro de la configuración del objeto yaxis
    fig.update_layout(
        template="plotly_white", 
        yaxis=dict(
            ticksuffix="%", 
            range=[0, df_counts["Proporcion_Porcentaje"].max() * 1.15]
        )
    )
    
    os.makedirs(PLOTS_DIR, exist_ok=True)
    fig.write_html(os.path.join(PLOTS_DIR, f"composition_{task_type}.html"))
    print(f"    [Gráfica Guardada] -> Proporciones Train/Test en {PLOTS_DIR}/composition_{task_type}.html")

if __name__ == "__main__":
    df_clean = load_and_clean_l4_strict(RAW_DATA_DIR)
    generate_split_and_plot(df_clean, "binary")
    generate_split_and_plot(df_clean, "multi")
    print(">>> MÓDULO 1: Completado con éxito.\n")