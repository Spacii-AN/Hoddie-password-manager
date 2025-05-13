import os
import shutil
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class BackupManager:
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.backup_dir = Path(user_manager.users_dir).parent / "backups"
        self.backup_dir.mkdir(exist_ok=True)
        
    def create_backup(self, username):
        """Create a backup of the user's database"""
        try:
            user_data = self.user_manager.user_registry["users"].get(username)
            if not user_data:
                logger.error(f"User {username} not found for backup")
                return False, "User not found"
                
            db_path = user_data["db_path"]
            if not os.path.exists(db_path):
                logger.error(f"Database file not found for user {username}")
                return False, "Database file not found"
                
            # Create timestamp for backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"{username}_{timestamp}.backup"
            
            # Copy the database file
            shutil.copy2(db_path, backup_path)
            
            # Create backup metadata
            metadata = {
                "username": username,
                "timestamp": timestamp,
                "original_path": db_path,
                "backup_path": str(backup_path),
                "version": user_data.get("security_version", "1.0")
            }
            
            # Save metadata
            metadata_path = backup_path.with_suffix(".json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
                
            logger.info(f"Created backup for user {username} at {backup_path}")
            return True, str(backup_path)
            
        except Exception as e:
            logger.error(f"Backup failed for user {username}: {str(e)}")
            return False, f"Backup failed: {str(e)}"
            
    def restore_backup(self, username, backup_path):
        """Restore a backup for the user"""
        try:
            user_data = self.user_manager.user_registry["users"].get(username)
            if not user_data:
                logger.error(f"User {username} not found for restore")
                return False, "User not found"
                
            backup_path = Path(backup_path)
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False, "Backup file not found"
                
            # Verify metadata
            metadata_path = backup_path.with_suffix(".json")
            if not metadata_path.exists():
                logger.error(f"Backup metadata not found: {metadata_path}")
                return False, "Backup metadata not found"
                
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                
            if metadata["username"] != username:
                logger.error(f"Backup username mismatch: {metadata['username']} != {username}")
                return False, "Backup username mismatch"
                
            # Create a backup of current database before restore
            current_db_path = user_data["db_path"]
            if os.path.exists(current_db_path):
                pre_restore_backup = self.backup_dir / f"{username}_pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.backup"
                shutil.copy2(current_db_path, pre_restore_backup)
                
            # Restore the backup
            shutil.copy2(backup_path, current_db_path)
            
            logger.info(f"Restored backup for user {username} from {backup_path}")
            return True, "Backup restored successfully"
            
        except Exception as e:
            logger.error(f"Restore failed for user {username}: {str(e)}")
            return False, f"Restore failed: {str(e)}"
            
    def list_backups(self, username):
        """List all backups for a user"""
        try:
            backups = []
            for backup_file in self.backup_dir.glob(f"{username}_*.backup"):
                metadata_path = backup_file.with_suffix(".json")
                if metadata_path.exists():
                    with open(metadata_path, "r") as f:
                        metadata = json.load(f)
                        backups.append({
                            "path": str(backup_file),
                            "timestamp": metadata["timestamp"],
                            "version": metadata["version"]
                        })
            return True, sorted(backups, key=lambda x: x["timestamp"], reverse=True)
        except Exception as e:
            logger.error(f"Failed to list backups for user {username}: {str(e)}")
            return False, f"Failed to list backups: {str(e)}"
            
    def delete_backup(self, backup_path):
        """Delete a backup file and its metadata"""
        try:
            backup_path = Path(backup_path)
            if not backup_path.exists():
                return False, "Backup file not found"
                
            metadata_path = backup_path.with_suffix(".json")
            
            # Delete both files
            backup_path.unlink()
            if metadata_path.exists():
                metadata_path.unlink()
                
            logger.info(f"Deleted backup: {backup_path}")
            return True, "Backup deleted successfully"
            
        except Exception as e:
            logger.error(f"Failed to delete backup {backup_path}: {str(e)}")
            return False, f"Failed to delete backup: {str(e)}" 