import os
import time
import requests
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EmailFileHandler(FileSystemEventHandler):
    def __init__(self, api_url: str):
        self.api_url = api_url
        self.processed_files = set()
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        filename = os.path.basename(file_path)
        
        # Only process .eml files
        if not filename.lower().endswith('.eml'):
            return
        
        # Avoid processing the same file multiple times
        if filename in self.processed_files:
            return
        
        logger.info(f"New email file detected: {filename}")
        
        # Wait a moment for file to be fully written
        time.sleep(2)
        
        try:
            # Upload file to API
            self.upload_file(file_path, filename)
            self.processed_files.add(filename)
            
        except Exception as e:
            logger.error(f"Error processing file {filename}: {e}")
    
    def upload_file(self, file_path: str, filename: str):
        """Upload file to the API"""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f, 'message/rfc822')}
                
                response = requests.post(
                    f"{self.api_url}/upload",
                    files=files,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"Successfully uploaded {filename}: {result}")
                else:
                    logger.error(f"Failed to upload {filename}: {response.status_code} - {response.text}")
                    
        except Exception as e:
            logger.error(f"Error uploading file {filename}: {e}")

class EmailWatcher:
    def __init__(self, watch_directory: str, api_url: str):
        self.watch_directory = watch_directory
        self.api_url = api_url
        self.observer = Observer()
        self.event_handler = EmailFileHandler(api_url)
    
    def start(self):
        """Start watching the directory"""
        logger.info(f"Starting to watch directory: {self.watch_directory}")
        
        # Ensure directory exists
        os.makedirs(self.watch_directory, exist_ok=True)
        
        # Start watching
        self.observer.schedule(
            self.event_handler,
            self.watch_directory,
            recursive=False
        )
        
        self.observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping file watcher...")
            self.observer.stop()
        
        self.observer.join()

def main():
    """Main entry point"""
    watch_directory = os.getenv("WATCH_DIRECTORY", "/watch/inbox")
    api_url = os.getenv("API_URL", "http://localhost:8080")
    
    logger.info(f"Email watcher starting...")
    logger.info(f"Watch directory: {watch_directory}")
    logger.info(f"API URL: {api_url}")
    
    watcher = EmailWatcher(watch_directory, api_url)
    watcher.start()

if __name__ == "__main__":
    main()
