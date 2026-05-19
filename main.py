"""
main.py  –  CIC-IDS2017  |  Preparación de Datos
=================================================
Cubre los puntos 1-6 del pipeline:
  1. Limpieza: elimina Heartbleed e Infiltration, combina subcategorías Web Attack
  2. One-hot encoding por puertos comunes y rangos de puertos
  3. Construye dataset binario (BENIGN vs ataque) y multiclase (solo ataques)
  4. Gráfico de distribución de clases (binario + multi) — escala log opcional
  5. Split train/test estratificado (85/15) y exportación
  6. Gráfico comparativo de proporciones train vs test (binario + multi)
"""

import pandas as pd
import numpy as np
import glob
import os
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

# Puertos well-known a codificar individualmente
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

# Clases a eliminar por estar subrepresentadas en CIC-IDS2017
CLASSES_TO_DROP = ["Infiltration", "Heartbleed"]

# Umbral mínimo de muestras para mantener una clase (seguridad adicional)
MIN_SAMPLES = 100

# ¿Usar escala logarítmica en las gráficas de distribución?
USE_LOG_SCALE = True

sns.set_theme(style="whitegrid", palette="muted")


# ──────────────────────────────────────────────────────────────────────────────
# 1. CARGA Y LIMPIEZA
# ──────────────────────────────────────────────────────────────────────────────
def load_and_clean(path_to_csvs: str) -> pd.DataFrame:
    """
    Carga todos los CSV del directorio, limpia y refina etiquetas.
    """
    print(">>> [1/6] Cargando y limpiando datos...")
    all_files = glob.glob(os.path.join(path_to_csvs, "*.csv"))
    if not all_files:
        raise FileNotFoundError(f"No se encontraron archivos CSV en: {path_to_csvs}")

    chunks = []
    for f in all_files:
        df_tmp = pd.read_csv(f, low_memory=False)
        df_tmp.columns = df_tmp.columns.str.strip()
        chunks.append(df_tmp)
    df = pd.concat(chunks, ignore_index=True)

    # ── Columnas a eliminar (no aportan información al modelo)
    cols_to_drop = ["Flow ID", "Source IP", "Source Port",
                    "Destination IP", "Timestamp"]
    df.drop(columns=[c for c in cols_to_drop if c in df.columns], inplace=True)

    # ── Valores infinitos y nulos
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(inplace=True)
    print(f"    Filas eliminadas por NaN/Inf: {before - len(df):,}")

    # ── Normalizar etiqueta
    df["Label"] = df["Label"].str.strip()

    # ── Eliminar clases subrepresentadas
    df = df[~df["Label"].isin(CLASSES_TO_DROP)].copy()

    # ── Combinar subcategorías de Web Attack en una sola categoría
    web_mask = df["Label"].str.contains("Web Attack", case=False, na=False)
    df.loc[web_mask, "Label"] = "Web_Attack"

    # ── Eliminar cualquier otra clase con muy pocas muestras
    class_counts = df["Label"].value_counts()
    rare = class_counts[class_counts < MIN_SAMPLES].index.tolist()
    if rare:
        print(f"    Clases adicionales eliminadas por baja representación (<{MIN_SAMPLES}): {rare}")
        df = df[~df["Label"].isin(rare)].copy()

    print(f"    Total de registros limpios: {len(df):,}")
    print(f"    Clases finales: {sorted(df['Label'].unique())}")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# 2. ENCODING DE PUERTOS
# ──────────────────────────────────────────────────────────────────────────────
def encode_ports(df: pd.DataFrame) -> pd.DataFrame:
    """
    One-hot encoding para puertos comunes + flags de rango de puerto.
    La columna original 'Destination Port' se elimina tras la codificación.
    """
    print(">>> [2/6] Codificando puertos...")
    port_col = "Destination Port"
    if port_col not in df.columns:
        print("    AVISO: 'Destination Port' no encontrado, se omite encoding.")
        return df

    port = df[port_col].astype(int)

    # Puertos individuales
    for p in COMMON_PORTS:
        df[f"Port_{p}"] = (port == p).astype(np.int8)

    # Rangos de puertos (IANA)
    df["Port_WellKnown"]  = (port <= 1023).astype(np.int8)           # 0–1023
    df["Port_Registered"] = ((port > 1023) & (port <= 49151)).astype(np.int8)  # 1024–49151
    df["Port_Dynamic"]    = (port > 49151).astype(np.int8)           # 49152–65535

    df.drop(columns=[port_col], inplace=True)
    print(f"    Columnas de puerto añadidas: {len(COMMON_PORTS) + 3}")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# 3. CONSTRUCCIÓN DE DATASETS
# ──────────────────────────────────────────────────────────────────────────────
def build_datasets(df: pd.DataFrame):
    """
    Retorna dos DataFrames:
      - df_binary: todos los registros con Label ∈ {0=BENIGN, 1=Ataque}
      - df_multi : solo registros de ataque con su categoría original
    """
    print(">>> [3/6] Construyendo datasets...")

    # Dataset binario
    df_binary = df.copy()
    df_binary["Label"] = df_binary["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    # Dataset multiclase (sin BENIGN)
    df_multi = df[df["Label"] != "BENIGN"].copy()

    print(f"    Binario  → {len(df_binary):,} registros  |  "
          f"Benign: {(df_binary['Label']==0).sum():,}  |  "
          f"Ataque: {(df_binary['Label']==1).sum():,}")
    print(f"    Multiclase → {len(df_multi):,} registros  |  "
          f"Categorías: {sorted(df_multi['Label'].unique())}")
    return df_binary, df_multi


# ──────────────────────────────────────────────────────────────────────────────
# 4. GRÁFICOS DE DISTRIBUCIÓN DE CLASES
# ──────────────────────────────────────────────────────────────────────────────
def _bar_distribution(ax, labels, counts, title, use_log=True, palette="muted"):
    """Helper: dibuja un barplot de distribución en el eje dado."""
    colors = sns.color_palette(palette, n_colors=len(labels))
    bars = ax.barh(labels, counts, color=colors, edgecolor="white", linewidth=0.6)
    ax.set_title(title, fontsize=13, fontweight="bold", pad=10)
    ax.set_xlabel("Número de muestras" + (" (log₁₀)" if use_log else ""), fontsize=10)

    if use_log:
        ax.set_xscale("log")
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(
            lambda x, _: f"{int(x):,}" if x >= 1 else ""
        ))
    else:
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(
            lambda x, _: f"{int(x):,}"
        ))

    # Etiquetas de valor al final de cada barra
    for bar, cnt in zip(bars, counts):
        ax.text(
            bar.get_width() * (1.03 if use_log else 1.01),
            bar.get_y() + bar.get_height() / 2,
            f"{cnt:,}", va="center", ha="left", fontsize=8.5
        )
    ax.invert_yaxis()
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)


def plot_class_distribution(df_binary: pd.DataFrame,
                             df_multi: pd.DataFrame,
                             use_log: bool = USE_LOG_SCALE):
    """
    Punto 4: Gráfico con la cantidad de datos por categoría (binaria y multi).
    """
    print(">>> [4/6] Graficando distribución de clases...")
    os.makedirs(PLOTS_DIR, exist_ok=True)

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("Distribución de Clases — CIC-IDS2017",
                 fontsize=15, fontweight="bold", y=1.01)

    # ── Panel izquierdo: binario
    bin_counts = df_binary["Label"].value_counts().sort_index()
    bin_labels = ["BENIGN (0)", "Ataque (1)"]
    _bar_distribution(axes[0], bin_labels, bin_counts.values,
                      "Dataset Binario", use_log=use_log, palette="Blues_d")

    # ── Panel derecho: multiclase
    mul_counts = df_multi["Label"].value_counts().sort_values(ascending=True)
    _bar_distribution(axes[1], mul_counts.index.tolist(), mul_counts.values,
                      "Dataset Multiclase (solo ataques)", use_log=use_log, palette="Oranges_d")

    log_tag = "_log" if use_log else ""
    save_path = os.path.join(PLOTS_DIR, f"class_distribution{log_tag}.png")
    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"    Guardado: {save_path}")


# ──────────────────────────────────────────────────────────────────────────────
# 5. SPLIT TRAIN / TEST Y EXPORTACIÓN
# ──────────────────────────────────────────────────────────────────────────────
def split_and_export(df: pd.DataFrame, task_type: str):
    """
    Punto 5: Split estratificado 85/15 y exportación de los 4 archivos CSV.
    Retorna (X_train, X_test, y_train, y_test) para uso posterior.
    """
    print(f">>> [5/6] Particionando y exportando dataset '{task_type}'...")

    output_dir = os.path.join(CLEAN_DATA_DIR, task_type)
    os.makedirs(output_dir, exist_ok=True)

    X = df.drop(columns=["Label"])
    y = df["Label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE
    )

    X_train.to_csv(f"{output_dir}/{task_type}_X_train.csv", index=False)
    y_train.to_csv(f"{output_dir}/{task_type}_y_train.csv", index=False)
    X_test.to_csv(f"{output_dir}/{task_type}_X_test.csv",  index=False)
    y_test.to_csv(f"{output_dir}/{task_type}_y_test.csv",  index=False)

    print(f"    Train: {len(X_train):,}  |  Test: {len(X_test):,}")
    print(f"    Archivos en: {output_dir}/")
    return X_train, X_test, y_train, y_test


# ──────────────────────────────────────────────────────────────────────────────
# 6. GRÁFICO DE PROPORCIÓN TRAIN vs TEST
# ──────────────────────────────────────────────────────────────────────────────
def plot_split_proportions(y_train, y_test, task_type: str,
                            label_map: dict = None,
                            use_log: bool = USE_LOG_SCALE):
    """
    Punto 6: Gráfico comparativo de proporciones de cada categoría
    en la partición de entrenamiento vs la de testeo.
    """
    print(f">>> [6/6] Graficando proporciones train/test — '{task_type}'...")

    def get_counts(y):
        s = pd.Series(y).value_counts().sort_index()
        if label_map:
            s.index = [label_map.get(i, str(i)) for i in s.index]
        return s

    train_counts = get_counts(y_train)
    test_counts  = get_counts(y_test)
    classes = sorted(set(train_counts.index) | set(test_counts.index))

    train_vals = [train_counts.get(c, 0) for c in classes]
    test_vals  = [test_counts.get(c, 0)  for c in classes]

    # ── Figura con dos subplots: conteo absoluto y proporción relativa
    fig, axes = plt.subplots(1, 2, figsize=(16, max(5, len(classes) * 0.55 + 2)))
    fig.suptitle(f"Distribución Train vs Test — {task_type.upper()}",
                 fontsize=14, fontweight="bold")

    x = np.arange(len(classes))
    width = 0.4
    palette = sns.color_palette("Set2", 2)

    for ax, vals_train, vals_test, title, is_log in [
        (axes[0], train_vals, test_vals, "Conteo Absoluto", use_log),
        (axes[1],
         [v / sum(train_vals) * 100 for v in train_vals],
         [v / sum(test_vals)  * 100 for v in test_vals],
         "Proporción Relativa (%)", False),
    ]:
        bars_train = ax.bar(x - width / 2, vals_train, width,
                            label="Train", color=palette[0], edgecolor="white")
        bars_test  = ax.bar(x + width / 2, vals_test,  width,
                            label="Test",  color=palette[1], edgecolor="white")

        if is_log and title == "Conteo Absoluto":
            ax.set_yscale("log")
            ax.yaxis.set_major_formatter(mticker.FuncFormatter(
                lambda x, _: f"{int(x):,}" if x >= 1 else ""))

        ax.set_xticks(x)
        ax.set_xticklabels(classes, rotation=35, ha="right", fontsize=9)
        ax.set_title(title, fontsize=12, fontweight="bold")
        ax.legend()
        ax.grid(axis="y", linestyle="--", alpha=0.5)
        ax.spines[["top", "right"]].set_visible(False)

        if title != "Conteo Absoluto":
            ax.set_ylabel("% del total del split")
            ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f%%"))

    log_tag = "_log" if use_log else ""
    save_path = os.path.join(PLOTS_DIR, f"split_proportions_{task_type}{log_tag}.png")
    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"    Guardado: {save_path}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("   CIC-IDS2017 — Pipeline de Preparación de Datos")
    print("=" * 60)

    # [1] Cargar y limpiar
    df_raw = load_and_clean(RAW_DATA_DIR)

    # [2] Encoding de puertos
    df_ready = encode_ports(df_raw)

    # [3] Construir datasets
    df_binary, df_multi = build_datasets(df_ready)

    # [4] Gráfico de distribución global
    plot_class_distribution(df_binary, df_multi, use_log=USE_LOG_SCALE)

    # [5] Split y exportación — Binario
    X_tr_bin, X_te_bin, y_tr_bin, y_te_bin = split_and_export(df_binary, "binary")

    # [5] Split y exportación — Multiclase
    X_tr_mul, X_te_mul, y_tr_mul, y_te_mul = split_and_export(df_multi, "multi")

    # [6] Gráfico de proporciones train/test
    label_map_bin = {0: "BENIGN", 1: "Ataque"}
    plot_split_proportions(y_tr_bin, y_te_bin, "binary",
                           label_map=label_map_bin, use_log=USE_LOG_SCALE)
    plot_split_proportions(y_tr_mul, y_te_mul, "multi",
                           use_log=USE_LOG_SCALE)

    print("\n" + "=" * 60)
    print("   Preparación completada. Archivos listos para entrenamiento.")
    print("=" * 60)