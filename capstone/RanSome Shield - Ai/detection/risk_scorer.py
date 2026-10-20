"""
Explainable Risk Scorer for Ransomware Behavior Analysis.
Calculates a risk score from 0 to 100 based on weighted behavioral heuristics
and maps it to standardized severity levels.
"""

class RiskScorer:
    def __init__(self, low_max=29, med_max=59, high_max=79):
        self.low_max = low_max
        self.med_max = med_max
        self.high_max = high_max

    def calculate_score(self, factors: dict) -> tuple[int, str, list[str]]:
        """
        Factors dictionary expected keys:
        - modification_count: int
        - rename_count: int
        - create_delete_count: int
        - unique_extensions_changed: int
        - time_span_seconds: float
        - known_suspicious_extension: bool
        - affected_files_count: int
        """
        score = 0
        reasons = []

        mod_count = factors.get('modification_count', 0)
        rename_count = factors.get('rename_count', 0)
        del_count = factors.get('delete_count', 0)
        create_count = factors.get('create_count', 0)
        ext_count = factors.get('unique_extensions_changed', 0)
        time_span = max(factors.get('time_span_seconds', 1.0), 0.5)
        suspicious_ext = factors.get('known_suspicious_extension', False)
        affected_files = factors.get('affected_files_count', 0)

        # 1. Modification rate factor
        mod_rate = mod_count / time_span
        if mod_rate >= 5.0:  # e.g., >5 mods per second
            score += 35
            reasons.append(f"High modification burst rate: {mod_count} files modified in {time_span:.1f}s ({mod_rate:.1f} ops/sec)")
        elif mod_rate >= 2.0 or mod_count >= 8:
            score += 20
            reasons.append(f"Elevated modification velocity: {mod_count} file changes in {time_span:.1f}s")
        elif mod_count >= 3:
            score += 10
            reasons.append(f"Moderate file modification activity: {mod_count} files")

        # 2. Rename / File movement rate (classic ransomware behavior)
        rename_rate = rename_count / time_span
        if rename_rate >= 3.0 or rename_count >= 6:
            score += 35
            reasons.append(f"Rapid mass renaming detected: {rename_count} renames in {time_span:.1f}s")
        elif rename_count >= 3:
            score += 20
            reasons.append(f"Multiple file renames detected: {rename_count} files")

        # 3. Create + Delete churn rate
        churn_count = del_count + create_count
        if churn_count >= 8:
            score += 25
            reasons.append(f"High file turnover/churn: {create_count} created, {del_count} deleted in {time_span:.1f}s")
        elif churn_count >= 4:
            score += 15
            reasons.append(f"Noticeable file churn: {create_count} created, {del_count} deleted")

        # 4. Extension entropy & shifting
        if suspicious_ext:
            score += 40
            reasons.append("Suspicious or pseudo-encrypted extension signature detected (e.g., .locked, .crypto, .enc)")
        elif ext_count >= 3:
            score += 25
            reasons.append(f"Multi-extension mutation observed across {ext_count} distinct extensions")
        elif ext_count >= 2:
            score += 10
            reasons.append(f"Extension divergence across {ext_count} extensions")

        # 5. Breadth of blast radius (spread across different folders/files)
        if affected_files >= 10:
            score += 15
            reasons.append(f"High target breadth: {affected_files} distinct files targeted concurrently")
        elif affected_files >= 5:
            score += 8
            reasons.append(f"Moderate target breadth: {affected_files} distinct files affected")

        # Normalize score between 0 and 100
        final_score = min(max(int(score), 0), 100)
        severity = self.get_severity(final_score)

        if not reasons:
            reasons.append("Baseline background activity within acceptable thresholds")

        return final_score, severity, reasons

    def get_severity(self, score: int) -> str:
        if score <= self.low_max:
            return 'Low'
        elif score <= self.med_max:
            return 'Medium'
        elif score <= self.high_max:
            return 'High'
        else:
            return 'Critical'
