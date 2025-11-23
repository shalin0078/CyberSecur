# cybersecure_model.py

import pandas as pd
import numpy as np
import joblib
import hashlib
import datetime
from functools import lru_cache
import sqlite3
import json
import os


# ========= CONFIG =========
MODEL_PATH = "cybersecure_model.pkl"
DEFAULT_THRESHOLD = 0.30
DB_PATH = "cybersecure.db"



# ========= MODEL LOADING (CACHED) =========
@lru_cache(maxsize=1)
def load_model():
    """
    Load the trained sklearn Pipeline from disk (only once).
    """
    return joblib.load(MODEL_PATH)

def get_db_connection():
    """
    Open a connection to the SQLite database.
    """
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    """
    Create the threat_logs table if it does not already exist.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            label INTEGER,
            label_text TEXT,
            probability REAL,
            severity TEXT,
            intrusion_type TEXT,
            action TEXT,
            reason TEXT,
            flow_json TEXT,
            prev_hash TEXT,
            hash TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def save_entry_to_db(entry: dict):
    """
    Save a single threat log entry dictionary into SQLite.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    flow_json = json.dumps(entry.get("flow", {}))

    cur.execute(
        """
        INSERT INTO threat_logs (
            timestamp,
            label,
            label_text,
            probability,
            severity,
            intrusion_type,
            action,
            reason,
            flow_json,
            prev_hash,
            hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.get("timestamp"),
            entry.get("label"),
            entry.get("label_text"),
            entry.get("probability"),
            entry.get("severity"),
            entry.get("intrusion_type"),
            entry.get("action"),
            entry.get("reason"),
            flow_json,
            entry.get("prev_hash"),
            entry.get("hash"),
        )
    )

    conn.commit()
    conn.close()


def load_threat_logs(limit: int = 1000):
    """
    Load last N threat logs from SQLite as a pandas DataFrame.
    Useful for a 'History' tab in the dashboard.
    """
    conn = get_db_connection()
    query = """
        SELECT
            id,
            timestamp,
            label,
            label_text,
            probability,
            severity,
            intrusion_type,
            action,
            reason,
            flow_json,
            prev_hash,
            hash
        FROM threat_logs
        ORDER BY id DESC
        LIMIT ?
    """
    df = pd.read_sql_query(query, conn, params=(limit,))
    conn.close()
    return df


# Initialize DB when module is imported
init_db()

# ========= ATTACK FAMILY / TRIAGE ENGINE (FROM YOUR CODE) =========

DOS = {"neptune", "smurf", "back", "teardrop", "pod", "land"}
PROBE = {"satan", "ipsweep", "portsweep", "nmap"}
R2L = {
    "guess_passwd", "ftp_write", "imap", "phf", "multihop",
    "warezmaster", "warezclient", "spy"
}
U2R = {"buffer_overflow", "rootkit", "loadmodule", "perl"}


def get_attack_family(label):
    label = str(label).lower()
    if label in DOS:
        return "DoS"
    if label in PROBE:
        return "Probe"
    if label in R2L:
        return "R2L"
    if label in U2R:
        return "U2R"
    if label == "normal":
        return "Normal"
    return "Unknown"


def get_severity(prob):
    if prob >= 0.90:
        return "High"
    elif prob >= 0.70:
        return "Medium"
    elif prob >= 0.30:
        return "Low"
    else:
        return "None"


def get_action(severity, family):
    if severity == "None":
        return "Allow"
    if severity == "Low":
        return "Log + Monitor"
    if severity == "Medium":
        return "Block IP + Alert SOC"
    if severity == "High":
        if family in ["R2L", "U2R"]:
            return "Immediate Quarantine + SOC Investigation"
        else:
            return "Block + Alert + Quarantine"
    return "Allow"


def triage_engine(label, prob, raw_label=None):
    """
    label: 0 (benign) or 1 (intrusion)
    prob: probability of intrusion (float)
    raw_label: original NSL-KDD label string (e.g. 'neptune', 'normal')
    """
    if label == 0:
        return {
            "severity": "None",
            "family": "Normal",
            "action": "Allow",
            "reason": "Flow classified as normal traffic."
        }

    family = get_attack_family(raw_label) if raw_label is not None else "Unknown"
    severity = get_severity(prob)
    action = get_action(severity, family)

    return {
        "severity": severity,
        "family": family,
        "action": action,
        "reason": f"Intrusion detected (prob {prob:.2f}), Family: {family}."
    }


# ========= THREAT LOG WITH HASH-CHAIN =========

threat_log = []
previous_hash = "0"


def compute_hash(data: str):
    return hashlib.sha256(data.encode()).hexdigest()


def add_log_entry(flow_dict, label, prob, triage, timestamp=None):
    """
    Create one log entry, hash it, append to global threat_log,
    and also persist it into SQLite.
    """
    global previous_hash, threat_log

    label_text = "Intrusion" if label == 1 else "Benign"
    
    ts_str = str(timestamp) if timestamp else str(datetime.datetime.now())

    entry = {
        "timestamp": ts_str,
        "label": int(label),              # 0/1 numeric
        "label_text": label_text,         # 'Benign' / 'Intrusion'
        "probability": float(prob),
        "severity": triage["severity"],
        "intrusion_type": triage.get("family", "Unknown"),
        "action": triage["action"],
        "reason": triage.get("reason", ""),
        "flow": flow_dict,               # original features
        "prev_hash": previous_hash,
    }

    # Compute hash for integrity chain
    entry_data = str(entry)
    current_hash = compute_hash(entry_data)
    entry["hash"] = current_hash

    # 1) In-memory chain (for current run / dashboard)
    threat_log.append(entry)
    previous_hash = current_hash

    # 2) Persistent storage in SQLite
    save_entry_to_db(entry)

    return entry



# ========= SINGLE-FLOW PREDICTION (OPTIONAL) =========

def predict_flow(flow_dict, threshold: float = DEFAULT_THRESHOLD):
    """
    Predict for a single flow dict (one row).
    Returns (label_0_or_1, prob_of_intrusion).
    """
    model = load_model()
    row_df = pd.DataFrame([flow_dict])
    proba = model.predict_proba(row_df)[0][1]
    label = 1 if proba >= threshold else 0
    return label, float(proba)


def process_flow(flow_dict, raw_label=None, threshold: float = DEFAULT_THRESHOLD):
    """
    End-to-end for a single flow:
    1) model prediction
    2) triage
    3) hash-logged entry
    """
    label, prob = predict_flow(flow_dict, threshold=threshold)
    triage = triage_engine(label, prob, raw_label=raw_label)
    entry = add_log_entry(flow_dict, label, prob, triage)
    return entry


# ========= BATCH PROCESSING FOR CSV (USED BY UI) =========

def process_batch(df: pd.DataFrame, threshold: float = DEFAULT_THRESHOLD):
    """
    Batch processing for a CSV uploaded in the UI.

    df: DataFrame from uploaded CSV.
        Can contain 'label' (original NSL-KDD label) and/or 'binary_label'.

    Returns:
        threat_df : DataFrame of triaged flows (one row per flow)
        feature_df: DataFrame of features actually fed into the model
    """
    global threat_log, previous_hash
    threat_log = []
    previous_hash = "0"

    # For attack family and explanation
    raw_label_series = df["label"] if "label" in df.columns else None

    # Remove columns that were not in X during training
    drop_cols = [c for c in ["label", "binary_label"] if c in df.columns]
    feature_df = df.drop(columns=drop_cols, errors="ignore").copy()

    model = load_model()
    probs = model.predict_proba(feature_df)[:, 1]
    labels = (probs >= threshold).astype(int)

    # Simulate timestamps spread over the last hour for better visualization
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(minutes=60)
    time_step = (end_time - start_time) / len(feature_df) if len(feature_df) > 0 else datetime.timedelta(seconds=1)

    entries = []
    for idx, (i, row) in enumerate(feature_df.iterrows()):
        flow_dict = row.to_dict()
        raw_label = raw_label_series.iloc[idx] if raw_label_series is not None else None
        triage = triage_engine(labels[idx], probs[idx], raw_label=raw_label)
        
        # Calculate timestamp for this entry
        current_ts = start_time + (time_step * idx)
        
        # We need to pass this timestamp to add_log_entry, but add_log_entry uses datetime.now() by default.
        # We'll modify add_log_entry to accept an optional timestamp or handle it here.
        # Since add_log_entry is simple, let's just manually create the entry here to override timestamp,
        # or better, update add_log_entry to accept it.
        
        # Let's update add_log_entry signature first.
        entry = add_log_entry(flow_dict, int(labels[idx]), float(probs[idx]), triage, timestamp=current_ts)
        entries.append(entry)

    threat_df = pd.DataFrame(entries)
    return threat_df, feature_df
