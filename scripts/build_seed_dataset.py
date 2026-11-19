"""Write ml/dataset/seed_samples.csv (the 30 original hand-written samples) and synthetic.csv."""
import ast
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ml.training.synthetic import generate  # noqa: E402

src = (ROOT / "legacy" / "model" / "train_model.py").read_text()
block = src[src.index("SAMPLES = ["): src.index("def train")]
samples = ast.literal_eval(block.split("=", 1)[1].rsplit("]", 1)[0].strip() + "]")
out = ROOT / "ml" / "dataset"


def write(name: str, rows, source: str) -> None:
    with open(out / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "source"])
        for text, label in rows:
            w.writerow([text, label, source])


write("seed_samples.csv", samples, "seed_original")
write("synthetic.csv", generate(600, 42), "synthetic")
print(len(samples), "seed rows written")
