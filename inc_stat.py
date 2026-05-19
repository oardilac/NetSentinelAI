"""
Incremental Statistics Engine
=============================
Lightweight, cache-free incremental statistics tracker.
Computes running mean, variance, and standard deviation using
Welford's online algorithm — no stored history required.

Inspired by the AfterImage / Kitsune incStat approach but simplified
for flow-level feature extraction.
"""

import math


class IncrementalStat:
    """Tracks running statistics (count, mean, variance, std, min, max) incrementally.

    No raw values are stored — only the sufficient statistics are kept,
    making this suitable for long-lived or high-volume flows.
    """

    __slots__ = ("count", "_mean", "_m2", "min_val", "max_val")

    def __init__(self):
        self.count: int = 0
        self._mean: float = 0.0
        self._m2: float = 0.0  # sum of squares of differences from the mean
        self.min_val: float = float('inf')
        self.max_val: float = float('-inf')

    def update(self, value: float) -> None:
        """Feed a new observation using Welford's online algorithm."""
        self.count += 1
        delta = value - self._mean
        self._mean += delta / self.count
        delta2 = value - self._mean
        self._m2 += delta * delta2

        # Track min and max
        if value < self.min_val:
            self.min_val = value
        if value > self.max_val:
            self.max_val = value

    @property
    def mean(self) -> float:
        return self._mean if self.count > 0 else 0.0

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self._m2 / (self.count - 1)  # sample variance (N-1), consistent with CICFlowMeter

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)
