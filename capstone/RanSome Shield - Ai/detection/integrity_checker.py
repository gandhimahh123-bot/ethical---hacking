import hashlib
import os
from pathlib import Path
from datetime import datetime
from config import Config

class IntegrityChecker:
    @staticmethod
    def calculate_sha256(file_path: Path | str, chunk_size: int = 65536) -> str | None:
        """
        Stream calculate SHA-256 hash in chunks.
        Returns None if file is inaccessible or cannot be opened.
        """
        path = Path(file_path)
        if not path.is_file():
            return None
            
        sha256 = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, OSError, IOError):
            return None

    @staticmethod
    def scan_directory(folder_path: Path | str, recursive: bool = True) -> list[dict]:
        """
        Scans a folder and returns file metadata and SHA-256 hashes.
        Excludes internal/system files safely.
        """
        root = Path(folder_path).resolve()
        if not root.exists() or not root.is_dir():
            return []

        results = []
        try:
            iterator = root.rglob('*') if recursive else root.glob('*')
            for path in iterator:
                # Skip symlinks that point outside root or directories
                if path.is_symlink() or not path.is_file():
                    continue
                
                # Check for ignored directories/names
                parts = path.relative_to(root).parts
                if any(part in Config.INTERNAL_IGNORED_NAMES or part.startswith('.') for part in parts):
                    continue

                try:
                    stat = path.stat()
                    file_size = stat.st_size
                    # Limit very large files from automatic scanning if desired
                    if file_size > Config.MAX_FILE_SIZE_HASH_MB * 1024 * 1024:
                        file_hash = "SKIPPED_LARGE_FILE"
                    else:
                        file_hash = IntegrityChecker.calculate_sha256(path)

                    if file_hash:
                        results.append({
                            'file_path': str(path),
                            'relative_path': str(path.relative_to(root)),
                            'sha256_hash': file_hash,
                            'file_size': file_size,
                            'last_modified': datetime.utcfromtimestamp(stat.st_mtime)
                        })
                except (OSError, PermissionError):
                    continue
        except Exception:
            pass

        return results

    @staticmethod
    def compare_against_baseline(folder_path: Path | str, baseline_records: list[dict], recursive: bool = True) -> dict:
        """
        Compares current directory state against baseline.
        Returns modified, missing, and new files.
        """
        current_files = IntegrityChecker.scan_directory(folder_path, recursive=recursive)
        current_map = {item['relative_path']: item for item in current_files}
        baseline_map = {item['relative_path']: item for item in baseline_records}

        modified = []
        missing = []
        new_files = []
        unchanged = []

        # Check existing baseline against current
        for rel_path, base in baseline_map.items():
            if rel_path not in current_map:
                missing.append({
                    'relative_path': rel_path,
                    'original_path': base['file_path'],
                    'expected_hash': base['sha256_hash']
                })
            else:
                curr = current_map[rel_path]
                if curr['sha256_hash'] != base['sha256_hash'] and curr['sha256_hash'] != 'SKIPPED_LARGE_FILE':
                    modified.append({
                        'relative_path': rel_path,
                        'file_path': curr['file_path'],
                        'expected_hash': base['sha256_hash'],
                        'current_hash': curr['sha256_hash'],
                        'file_size': curr['file_size']
                    })
                else:
                    unchanged.append(rel_path)

        # Check for newly created files not present in baseline
        for rel_path, curr in current_map.items():
            if rel_path not in baseline_map:
                new_files.append({
                    'relative_path': rel_path,
                    'file_path': curr['file_path'],
                    'sha256_hash': curr['sha256_hash'],
                    'file_size': curr['file_size']
                })

        status = 'clean'
        if modified or missing or new_files:
            status = 'anomalies_detected'

        return {
            'status': status,
            'total_current': len(current_files),
            'total_baseline': len(baseline_records),
            'modified_files': modified,
            'missing_files': missing,
            'new_files': new_files,
            'unchanged_count': len(unchanged),
            'checked_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }
