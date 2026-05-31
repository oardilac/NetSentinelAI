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
RAW_DATA_DIR = "./DataRaw"
CLEAN_DATA_DIR = "./DataClean"
RESULTS_DIR = "./Results"
PLOTS_DIR = "./Results/plots"
MODELS_DIR = "./Models"


def build_resampling_strategies(y_train):
    """
    Compute SMOTE and random under-sampler strategies based on class distribution.

    Args:
        y_train: target array with class labels

    Returns:
        (under_strat, over_strat): dicts mapping class label to target count
    """
    from collections import Counter
    counts = Counter(y_train)
    under_strat = {k: UNDER_SAMPLE_TARGET for k, v in counts.items() if v > UNDER_SAMPLE_TARGET}
    over_strat = {k: OVER_SAMPLE_TARGET for k, v in counts.items() if v < OVER_SAMPLE_TARGET}
    return under_strat, over_strat


def build_ml_pipeline(clf, task_type: str = "binary"):
    """
    Construct a scikit-learn/imblearn pipeline with scaler and optional resampling.

    Extracts common pipeline construction logic used in grid search (03_gridsearch.py)
    and final evaluation (04_eval.py).

    Args:
        clf: classifier instance (LGBMClassifier, XGBClassifier, RandomForestClassifier, etc.)
        task_type: "binary" (under-sampling only) or "multi" (under + over-sampling)

    Returns:
        imblearn.pipeline.Pipeline with steps: [scaler, [under], [smote], clf]
    """
    from sklearn.preprocessing import RobustScaler
    from imblearn.pipeline import Pipeline as ImbPipeline
    from imblearn.over_sampling import SMOTE
    from imblearn.under_sampling import RandomUnderSampler

    steps = [('scaler', RobustScaler())]

    if task_type == "binary":
        steps.append(('under', RandomUnderSampler(sampling_strategy="majority", random_state=RANDOM_STATE)))
    else:
        # Multi-class: compute strategies dynamically (caller must provide y_train context)
        # For multi-task, resampling steps are added conditionally by caller
        pass

    steps.append(('clf', clf))
    return ImbPipeline(steps=steps)


__all__ = [
    "RANDOM_STATE",
    "UNDER_SAMPLE_TARGET",
    "OVER_SAMPLE_TARGET",
    "SMOTE_K_NEIGHBORS",
    "CV_SPLITS",
    "CV_SCORING",
    "RAW_DATA_DIR",
    "CLEAN_DATA_DIR",
    "RESULTS_DIR",
    "PLOTS_DIR",
    "MODELS_DIR",
    "build_resampling_strategies",
    "build_ml_pipeline",
]
