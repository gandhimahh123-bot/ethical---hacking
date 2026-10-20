import tempfile
from pathlib import Path
from detection.integrity_checker import IntegrityChecker

def test_sha256_calculation_and_consistency():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "sample_doc.txt"
        test_file.write_text("Integrity Check Sample Payload Data 2026", encoding='utf-8')

        hash1 = IntegrityChecker.calculate_sha256(test_file)
        hash2 = IntegrityChecker.calculate_sha256(test_file)

        assert hash1 is not None
        assert len(hash1) == 64
        assert hash1 == hash2

def test_baseline_comparison_anomalies():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        f1 = root / "unchanged.txt"
        f2 = root / "modified.txt"
        f3 = root / "deleted.txt"

        f1.write_text("Hello Clean File 1", encoding='utf-8')
        f2.write_text("Original State File 2", encoding='utf-8')
        f3.write_text("File to be deleted", encoding='utf-8')

        # Generate baseline
        baseline = IntegrityChecker.scan_directory(root, recursive=True)
        assert len(baseline) == 3

        # Modify f2, delete f3, create f4
        f2.write_text("TAMPERED State File 2", encoding='utf-8')
        f3.unlink()
        f4 = root / "untracked_new.txt"
        f4.write_text("New file data", encoding='utf-8')

        # Compare
        result = IntegrityChecker.compare_against_baseline(root, baseline, recursive=True)
        
        assert result['status'] == 'anomalies_detected'
        assert len(result['modified_files']) == 1
        assert result['modified_files'][0]['relative_path'] == 'modified.txt'
        assert len(result['missing_files']) == 1
        assert result['missing_files'][0]['relative_path'] == 'deleted.txt'
        assert len(result['new_files']) == 1
        assert result['new_files'][0]['relative_path'] == 'untracked_new.txt'
