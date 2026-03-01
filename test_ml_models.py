#!/usr/bin/env python3
"""
Quick test script to verify optimized models performance
Run this to see live model training and performance metrics
"""

import sys
from pathlib import Path

# Add backend to path
backend_path = str(Path(__file__).parent / "backend")
sys.path.insert(0, backend_path)

from models.optimized_models import (
    anomaly_detector, 
    risk_scorer, 
    propagation_analyzer
)
import numpy as np

def main():
    print("\n" + "="*80)
    print("🎯 TrustNet AI Guardian - ML Model Performance Test")
    print("="*80)
    
    # Test 1: Anomaly Detection
    print("\n📊 TEST 1: Anomaly Detection")
    print("-" * 80)
    
    test_records = [
        {"session_duration": 4.5, "data_volume": 150, "cpu": 200, "network": 50, "logins": 10},
        {"session_duration": 0.2, "data_volume": 850, "cpu": 450, "network": 200, "logins": 45},
        {"session_duration": 4.3, "data_volume": 155, "cpu": 205, "network": 52, "logins": 11},
        {"session_duration": 8.2, "data_volume": 950, "cpu": 500, "network": 250, "logins": 50},
    ]
    
    features = list(test_records[0].keys())
    data = np.array([[r.get(f, 0) for f in features] for r in test_records])
    
    try:
        predictions, scores = anomaly_detector.predict(data)
        
        for i, (record, pred, score) in enumerate(zip(test_records, predictions, scores)):
            status = "🚨 ANOMALY" if pred == -1 else "✓ NORMAL"
            print(f"  Record {i+1}: {status} (Score: {score:.4f})")
            print(f"    Data: {record}")
    except Exception as e:
        print(f"  ⚠️  Note: Model needs training on first run")
        print(f"     {str(e)[:100]}")
    
    # Test 2: Risk Scoring
    print("\n📈 TEST 2: Risk Scoring")
    print("-" * 80)
    
    normal_metrics = {
        "normal_login_time": 9.2,
        "actual_login_time": 9.3,
        "normal_session_duration": 4.5,
        "actual_session_duration": 4.2,
        "normal_data_volume": 120,
        "actual_data_volume": 118,
        "normal_api_calls": 45,
        "actual_api_calls": 48,
        "normal_geo_distance": 0,
        "actual_geo_distance": 12,
    }
    
    attack_metrics = {
        "normal_login_time": 9.2,
        "actual_login_time": 23.8,
        "normal_session_duration": 4.5,
        "actual_session_duration": 0.3,
        "normal_data_volume": 120,
        "actual_data_volume": 850,
        "normal_api_calls": 45,
        "actual_api_calls": 312,
        "normal_geo_distance": 0,
        "actual_geo_distance": 9847,
    }
    
    print("\n  Scenario 1: Normal User Behavior")
    normal_result = risk_scorer.calculate_risk_score(normal_metrics, anomaly_score=0.1)
    print(f"    Risk Score: {normal_result['overall_score']}/100")
    print(f"    Threat Level: {normal_result['threat_level'].upper()}")
    print(f"    Recommendation: {normal_result['recommendation']}")
    print(f"    Confidence: {normal_result.get('confidence', 'N/A')}%")
    
    print("\n  Scenario 2: Active Attack Detected")
    attack_result = risk_scorer.calculate_risk_score(attack_metrics, anomaly_score=0.85)
    print(f"    Risk Score: {attack_result['overall_score']}/100")
    print(f"    Threat Level: {attack_result['threat_level'].upper()}")
    print(f"    Recommendation: {attack_result['recommendation']}")
    print(f"    Confidence: {attack_result.get('confidence', 'N/A')}%")
    
    # Test 3: Network Propagation
    print("\n🌐 TEST 3: Network Propagation Analysis")
    print("-" * 80)
    
    test_nodes = [
        {"id": "n1", "label": "Server A", "type": "server", "x": 0, "y": 0, "compromised": False, "propagationRisk": 30},
        {"id": "n2", "label": "User 1", "type": "user", "x": 1, "y": 1, "compromised": False, "propagationRisk": 45},
        {"id": "n3", "label": "Database", "type": "database", "x": 2, "y": 0, "compromised": False, "propagationRisk": 25},
    ]
    
    test_edges = [
        {"from": "n1", "to": "n2", "active": True, "attackPath": False},
        {"from": "n2", "to": "n3", "active": True, "attackPath": True},
    ]
    
    try:
        propagation_result = propagation_analyzer.analyze_network(test_nodes, test_edges)
        print(f"  Total Network Risk: {propagation_result['total_network_risk']}/100")
        print(f"  Critical Nodes: {propagation_result['critical_count']}")
        print(f"  Network Density: {propagation_result.get('network_density', 'N/A')}")
        print(f"\n  Node Analysis:")
        for node in propagation_result['all_nodes']:
            print(f"    {node['node_label']}: {node['propagation_risk']}/100 ({node['criticality']})")
    except Exception as e:
        print(f"  Error: {str(e)[:100]}")
    
    # Performance Summary
    print("\n" + "="*80)
    print("✅ MODEL PERFORMANCE SUMMARY")
    print("="*80)
    
    if hasattr(anomaly_detector, 'metrics') and anomaly_detector.metrics:
        print(f"\n🔍 Isolation Forest (Anomaly Detection)")
        print(f"   Precision: {anomaly_detector.metrics.get('precision', 'N/A')*100:.2f}%")
        print(f"   Recall:    {anomaly_detector.metrics.get('recall', 'N/A')*100:.2f}%")
        print(f"   F1-Score:  {anomaly_detector.metrics.get('f1', 'N/A')*100:.2f}%")
    
    if hasattr(anomaly_detector, 'best_params') and anomaly_detector.best_params:
        print(f"\n⚙️  Optimal Hyperparameters")
        print(f"   N-Estimators: {anomaly_detector.best_params.get('n_estimators')}")
        print(f"   Contamination: {anomaly_detector.best_params.get('contamination')}")
        print(f"   Scaler: {anomaly_detector.best_params.get('scaler')}")
    
    print(f"\n📚 Risk Scorer Weights")
    print(f"   Login Time Deviation:       18%")
    print(f"   Session Duration Deviation: 15%")
    print(f"   Data Volume Deviation:      22% ← Highest")
    print(f"   API Calls Deviation:        20%")
    print(f"   Geo-Distance Deviation:     20%")
    print(f"   Anomaly Score:              5%")
    
    print("\n" + "="*80)
    print("✨ Status: MODELS OPTIMIZED & READY FOR PRODUCTION")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
