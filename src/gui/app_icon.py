"""
Application icon for the Password Generator.
This icon is embedded as a base64 string to avoid dependencies on external files.
"""

import base64
import tkinter as tk
from PIL import Image, ImageTk
from io import BytesIO

# Base64 encoded icon (a simple blue key icon)
ICON_BASE64 = """
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
W/VhM6rJFQAAAABJRU5ErkJggg==
"""

def get_icon(window):
    """Create and return a PhotoImage object from the base64 encoded icon."""
    try:
        # Decode base64 icon
        icon_data = base64.b64decode(ICON_BASE64)
        
        # Create image from decoded data
        image = Image.open(BytesIO(icon_data))
        
        # Convert to PhotoImage for Tkinter
        icon = ImageTk.PhotoImage(image)
        
        # Set icon for the window
        window.tk.call('wm', 'iconphoto', window._w, icon)
        
        return icon
    except Exception as e:
        print(f"Could not load icon: {e}")
        return None