"""
evaluation.py
Benchmark evaluation script for PromptShield-XAI.
Runs the classifier against a test dataset, calculates metrics, 
and generates publication-ready matplotlib visualizations.
"""

import pandas as pd
import time
import json
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Import your classifier
from models.classifier import classify_prompt

def run_evaluation(dataset_path: str = "data/malicious_prompts.csv", output_dir: str = "results"):
    print("🚀 Starting PromptShield-XAI Evaluation Benchmark...\n")
    
    # 1. Load Dataset
    try:
        df = pd.read_csv(dataset_path)
        print(f"✅ Loaded {len(df)} prompts from {dataset_path}")
    except FileNotFoundError:
        print(f"❌ Error: Could not find {dataset_path}. Make sure the data folder exists.")
        return

    # 2. Run Predictions
    y_true = df['label'].tolist()  # 1 for malicious, 0 for safe
    y_pred = []
    
    start_time = time.time()
    
    print("⏳ Running classification engine...")
    for idx, row in df.iterrows():
        prompt = row['prompt']
        result = classify_prompt(prompt)
        prediction = 1 if result["is_threat"] else 0
        y_pred.append(prediction)
        
    end_time = time.time()
    processing_time = end_time - start_time

    # 3. Calculate Metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    # 4. Print Results to Console
    print("\n" + "="*40)
    print("📊 BENCHMARK RESULTS")
    print("="*40)
    print(f"Accuracy             : {accuracy * 100:.1f}%")
    print(f"Precision            : {precision * 100:.1f}%")
    print(f"Recall               : {recall * 100:.1f}%")
    print(f"F1-Score             : {f1 * 100:.1f}%")
    print("="*40 + "\n")

    # 5. Create Results Directory
    os.makedirs(output_dir, exist_ok=True)

    # ---------------------------------------------------------
    # 🎨 VISUALIZATION 1: Confusion Matrix Heatmap
    # ---------------------------------------------------------
    print("🎨 Generating Confusion Matrix Heatmap...")
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=['Predicted Safe', 'Predicted Threat'],
                yticklabels=['Actual Safe', 'Actual Threat'],
                annot_kws={"size": 14})
    plt.title('PromptShield-XAI Confusion Matrix', fontsize=14, pad=15)
    plt.tight_layout()
    cm_path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()

    # ---------------------------------------------------------
    # 🎨 VISUALIZATION 2: Performance Metrics Bar Chart
    # ---------------------------------------------------------
    print("🎨 Generating Metrics Bar Chart...")
    metrics_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    metrics_values = [accuracy, precision, recall, f1]
    
    plt.figure(figsize=(8, 5))
    colors = ['#4C72B0', '#55A868', '#C44E52', '#8172B2']
    bars = plt.bar(metrics_names, metrics_values, color=colors, width=0.6)
    
    plt.ylim(0, 1.1)
    plt.title('Model Performance Metrics', fontsize=14, pad=15)
    plt.ylabel('Score (0.0 to 1.0)', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add value labels on top of the bars
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.02, 
                 f"{yval*100:.1f}%", ha='center', va='bottom', fontsize=11, fontweight='bold')
                 
    plt.tight_layout()
    bar_path = os.path.join(output_dir, "metrics_bar_chart.png")
    plt.savefig(bar_path, dpi=300)
    plt.close()

    # 6. Save JSON Report
    report = {
        "metrics": {"accuracy": round(accuracy, 3), "precision": round(precision, 3), "recall": round(recall, 3), "f1_score": round(f1, 3)},
        "confusion_matrix": {"true_positive": int(tp), "true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn)}
    }
    report_path = os.path.join(output_dir, "benchmark_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"✅ Visualizations saved to '{output_dir}/' as PNG files!")

if __name__ == "__main__":
    run_evaluation()