from watchdog.events import FileSystemEventHandler
from pathlib import Path
from config import Config

class ShieldEventHandler(FileSystemEventHandler):
    def __init__(self, folder_id: int, base_path: str, event_callback):
        super().__init__()
        self.folder_id = folder_id
        self.base_path = Path(base_path).resolve()
        self.event_callback = event_callback

    def _is_ignored(self, path_str: str) -> bool:
        """
        Verify path does not touch internal application files, databases,
        backups, quarantine directories, or ignored OS files.
        """
        try:
            p = Path(path_str).resolve()
            
            # Prevent monitoring the application's instance, backups, quarantine, or db directly
            if Config.INSTANCE_DIR in p.parents or p == Config.INSTANCE_DIR:
                # Unless it's explicitly inside the demo sandbox
                if not (Config.DEMO_DIR in p.parents or p == Config.DEMO_DIR):
                    return True

            for part in p.parts:
                if part in Config.INTERNAL_IGNORED_NAMES or part.startswith('.~'):
                    return True
                    
            return False
        except Exception:
            return True

    def on_created(self, event):
        if event.is_directory or self._is_ignored(event.src_path):
            return
        self.event_callback('created', event.src_path, folder_id=self.folder_id)

    def on_modified(self, event):
        if event.is_directory or self._is_ignored(event.src_path):
            return
        self.event_callback('modified', event.src_path, folder_id=self.folder_id)

    def on_deleted(self, event):
        if event.is_directory or self._is_ignored(event.src_path):
            return
        self.event_callback('deleted', event.src_path, folder_id=self.folder_id)

    def on_moved(self, event):
        if event.is_directory or self._is_ignored(event.dest_path):
            return
        self.event_callback('moved', event.dest_path, old_path=event.src_path, folder_id=self.folder_id)
