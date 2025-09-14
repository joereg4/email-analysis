import os
import json
from typing import Dict, Any, Optional
import logging
from datetime import datetime

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)

class EXIFScanner:
    def __init__(self):
        if not PIL_AVAILABLE:
            logger.warning("PIL/Pillow not available. EXIF scanning will be limited.")
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan image file for EXIF metadata"""
        result = {
            'file_path': file_path,
            'has_exif': False,
            'exif_data': {},
            'gps_data': {},
            'suspicious_metadata': [],
            'risk_score': 0.0,
            'scan_timestamp': datetime.utcnow().isoformat()
        }
        
        if not PIL_AVAILABLE:
            result['error'] = 'PIL/Pillow not available'
            return result
        
        try:
            with Image.open(file_path) as image:
                exif_data = image._getexif()
                
                if exif_data is not None:
                    result['has_exif'] = True
                    result['exif_data'] = self._extract_exif_data(exif_data)
                    result['gps_data'] = self._extract_gps_data(exif_data)
                    result['suspicious_metadata'] = self._check_suspicious_metadata(result['exif_data'])
                    result['risk_score'] = self._calculate_exif_risk_score(result)
                else:
                    result['exif_data'] = {}
                    result['gps_data'] = {}
                    result['suspicious_metadata'] = []
                    result['risk_score'] = 0.0
                    
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Error scanning EXIF data for {file_path}: {e}")
        
        return result
    
    def _extract_exif_data(self, exif_data: Dict) -> Dict[str, Any]:
        """Extract and decode EXIF data"""
        extracted_data = {}
        
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            
            # Convert bytes to string if necessary
            if isinstance(value, bytes):
                try:
                    value = value.decode('utf-8', errors='ignore')
                except:
                    value = str(value)
            
            # Handle GPS data separately
            if tag == 'GPSInfo':
                continue
            
            extracted_data[tag] = value
        
        return extracted_data
    
    def _extract_gps_data(self, exif_data: Dict) -> Dict[str, Any]:
        """Extract GPS data from EXIF"""
        gps_data = {}
        
        if 'GPSInfo' in exif_data:
            gps_info = exif_data['GPSInfo']
            
            for key in gps_info.keys():
                name = GPSTAGS.get(key, key)
                gps_data[name] = gps_info[key]
            
            # Convert GPS coordinates to decimal degrees
            if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                lat = self._convert_to_degrees(gps_data['GPSLatitude'])
                lon = self._convert_to_degrees(gps_data['GPSLongitude'])
                
                # Apply hemisphere
                if gps_data.get('GPSLatitudeRef') == 'S':
                    lat = -lat
                if gps_data.get('GPSLongitudeRef') == 'W':
                    lon = -lon
                
                gps_data['decimal_latitude'] = lat
                gps_data['decimal_longitude'] = lon
        
        return gps_data
    
    def _convert_to_degrees(self, value) -> float:
        """Convert GPS coordinates to decimal degrees"""
        if isinstance(value, (list, tuple)) and len(value) == 3:
            d, m, s = value
            return float(d) + float(m) / 60.0 + float(s) / 3600.0
        return float(value)
    
    def _check_suspicious_metadata(self, exif_data: Dict[str, Any]) -> list:
        """Check for suspicious EXIF metadata"""
        suspicious = []
        
        # Check for suspicious software
        software = exif_data.get('Software', '').lower()
        suspicious_software = [
            'photoshop', 'gimp', 'paint', 'editor', 'modify', 'edit'
        ]
        
        for sw in suspicious_software:
            if sw in software:
                suspicious.append(f'Suspicious software: {exif_data.get("Software")}')
                break
        
        # Check for unusual camera settings
        if exif_data.get('Flash') == 0 and exif_data.get('ExposureTime', 0) > 1:
            suspicious.append('Unusual camera settings detected')
        
        # Check for metadata that might indicate manipulation
        if 'XPComment' in exif_data or 'XPKeywords' in exif_data:
            suspicious.append('Windows-specific metadata found')
        
        # Check for unusual resolution
        width = exif_data.get('ExifImageWidth', 0)
        height = exif_data.get('ExifImageHeight', 0)
        
        if width > 0 and height > 0:
            if width * height > 50_000_000:  # Very high resolution
                suspicious.append('Unusually high resolution image')
            elif width * height < 10000:  # Very low resolution
                suspicious.append('Unusually low resolution image')
        
        # Check for missing common metadata
        required_fields = ['Make', 'Model', 'DateTime']
        missing_fields = [field for field in required_fields if field not in exif_data]
        
        if len(missing_fields) > 1:
            suspicious.append(f'Missing common metadata: {", ".join(missing_fields)}')
        
        return suspicious
    
    def _calculate_exif_risk_score(self, result: Dict[str, Any]) -> float:
        """Calculate risk score based on EXIF analysis"""
        risk_score = 0.0
        
        # GPS data presence
        if result['gps_data']:
            risk_score += 10.0
        
        # Suspicious metadata
        risk_score += len(result['suspicious_metadata']) * 5.0
        
        # Missing required fields
        exif_data = result['exif_data']
        required_fields = ['Make', 'Model', 'DateTime']
        missing_fields = [field for field in required_fields if field not in exif_data]
        risk_score += len(missing_fields) * 3.0
        
        return min(risk_score, 50.0)  # Cap at 50 points for EXIF
    
    def get_image_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic image information"""
        info = {
            'file_path': file_path,
            'format': None,
            'mode': None,
            'size': None,
            'width': None,
            'height': None,
            'has_transparency': False
        }
        
        if not PIL_AVAILABLE:
            info['error'] = 'PIL/Pillow not available'
            return info
        
        try:
            with Image.open(file_path) as image:
                info['format'] = image.format
                info['mode'] = image.mode
                info['size'] = image.size
                info['width'] = image.width
                info['height'] = image.height
                info['has_transparency'] = image.mode in ('RGBA', 'LA') or 'transparency' in image.info
                
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def check_image_integrity(self, file_path: str) -> Dict[str, Any]:
        """Check image file integrity"""
        integrity = {
            'file_path': file_path,
            'is_valid': False,
            'corruption_detected': False,
            'issues': []
        }
        
        if not PIL_AVAILABLE:
            integrity['error'] = 'PIL/Pillow not available'
            return integrity
        
        try:
            with Image.open(file_path) as image:
                # Try to load the image
                image.load()
                integrity['is_valid'] = True
                
                # Check for common corruption issues
                if image.size == (0, 0):
                    integrity['corruption_detected'] = True
                    integrity['issues'].append('Zero dimensions')
                
                # Check for unusual color modes
                if image.mode not in ['RGB', 'RGBA', 'L', 'LA', 'P', 'CMYK']:
                    integrity['issues'].append(f'Unusual color mode: {image.mode}')
                
        except Exception as e:
            integrity['corruption_detected'] = True
            integrity['issues'].append(f'Image loading error: {str(e)}')
        
        return integrity

# Example usage
if __name__ == "__main__":
    scanner = EXIFScanner()
    
    # Test with a sample image
    sample_file = "sample.jpg"
    if os.path.exists(sample_file):
        result = scanner.scan_file(sample_file)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("No sample image file found for testing")
