import time
import pytest
from detection.risk_scorer import RiskScorer
from detection.behavior_detector import BehaviorDetector

def test_risk_scorer_low():
    scorer = RiskScorer()
    factors = {
        'modification_count': 1,
        'rename_count': 0,
        'create_count': 1,
        'delete_count': 0,
        'unique_extensions_changed': 1,
        'time_span_seconds': 5.0,
        'known_suspicious_extension': False,
        'affected_files_count': 1
    }
    score, severity, reasons = scorer.calculate_score(factors)
    assert 0 <= score <= 29
    assert severity == 'Low'
    assert len(reasons) > 0

def test_risk_scorer_critical_mass_rename_and_extension():
    scorer = RiskScorer()
    factors = {
        'modification_count': 15,
        'rename_count': 10,
        'create_count': 5,
        'delete_count': 5,
        'unique_extensions_changed': 4,
        'time_span_seconds': 2.0,
        'known_suspicious_extension': True,
        'affected_files_count': 12
    }
    score, severity, reasons = scorer.calculate_score(factors)
    assert score >= 80
    assert severity == 'Critical'
    assert any('extension' in r.lower() for r in reasons)
    assert any('renam' in r.lower() for r in reasons)

def test_behavior_detector_rapid_modifications():
    detector = BehaviorDetector(window_seconds=5, mod_threshold=4, cooldown_seconds=0)
    
    # Send 3 modifications - should not trigger yet
    assert detector.process_event('modified', '/safe/path/file1.txt') is None
    assert detector.process_event('modified', '/safe/path/file2.txt') is None
    assert detector.process_event('modified', '/safe/path/file3.txt') is None
    
    # 4th modification reaches threshold -> triggers alert
    alert = detector.process_event('modified', '/safe/path/file4.txt')
    assert alert is not None
    assert alert['risk_score'] > 0
    assert 'reasons' in alert

def test_behavior_detector_cooldown_deduplication():
    detector = BehaviorDetector(window_seconds=5, mod_threshold=2, cooldown_seconds=10)
    
    # Trigger 1st alert
    detector.process_event('modified', '/target/folder/a.txt')
    alert1 = detector.process_event('modified', '/target/folder/b.txt')
    assert alert1 is not None

    # Immediate next event in same folder should be suppressed by cooldown
    alert2 = detector.process_event('modified', '/target/folder/c.txt')
    assert alert2 is None
