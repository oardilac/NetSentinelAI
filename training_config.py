"""
Shared configuration constants for the ML training pipeline (01–04 modules).

All numeric thresholds and hyperparameters should be defined here to ensure
consistency across grid search, final evaluation, and other pipeline stages.
"""

# Core training settings
RANDOM_STATE = 42

# Class balancing thresholds (applied uniformly across gridsearch and final eval)
UNDER_SAMPLE_TARGET = 50_000  # Downsample majority classes larger than this
OVER_SAMPLE_TARGET = 15_000   # Upsample minority classes smaller than this

# SMOTE and resampling
SMOTE_K_NEIGHBORS = 3

# Cross-validation
CV_SPLITS = 5
CV_SCORING = "f1_macro"

# Data directories
CLEAN_DATA_DIR = "./DataClean"
RESULTS_DIR = "./Results"
PLOTS_DIR = "./Results/plots"
MODELS_DIR = "./Models"

__all__ = [
    "RANDOM_STATE",
    "UNDER_SAMPLE_TARGET",
    "OVER_SAMPLE_TARGET",
    "SMOTE_K_NEIGHBORS",
    "CV_SPLITS",
    "CV_SCORING",
    "CLEAN_DATA_DIR",
    "RESULTS_DIR",
    "PLOTS_DIR",
    "MODELS_DIR",
]
