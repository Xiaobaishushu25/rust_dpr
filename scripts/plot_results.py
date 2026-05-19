from __future__ import annotations

import argparse
from pathlib import Path

from common import read_json


def require_matplotlib():
    try:
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        raise SystemExit("matplotlib is required: pip install matplotlib")


def plot_bar(metric_json: Path, out: Path, metric: str) -> None:
    plt = require_matplotlib()
    data = read_json(metric_json)
    groups = data.get("by_tool_variant", {})
    labels = list(groups.keys())
    values = [groups[k].get(metric, 0.0) for k in labels]

    out.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 0.8), 4))
    ax.bar(labels, values)
    ax.set_ylabel(metric)
    ax.set_ylim(0, 1)
    ax.tick_params(axis="x", rotation=35)
    fig.tight_layout()
    fig.savefig(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--metric", default="mcp")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    plot_bar(Path(args.metrics), Path(args.out), args.metric)
    print(f"[done] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
