"""
Theme Stylesheet for Password Generator GUI

This module provides styling for the password generator GUI application,
with support for both light and dark themes.
"""

import tkinter as tk
from tkinter import ttk


class ThemeManager:
    """Manages themes and styling for the application."""
    
    def __init__(self, root):
        """Initialize the theme manager with a root window."""
        self.root = root
        self.style = ttk.Style()
        
        # Define color schemes
        self.color_schemes = {
            "light": {
                "bg": "#f5f5f7",               # Light background
                "fg": "#333333",               # Dark text
                "button_bg": "#e0e0e5",        # Button background
                "button_fg": "#333333",        # Button text
                "highlight_bg": "#3a5ab4",     # Highlight background (darker blue)
                "highlight_fg": "#ffffff",     # Highlight text
                "entry_bg": "white",           # Entry background
                "notebook_bg": "#f0f0f5",      # Notebook background
                "border": "#cccccc",           # Border color
                "success": "#4cd964",          # Success color (green)
                "scrollbar": "#d0d0d5"         # Scrollbar color
            },
            "dark": {
                "bg": "#202124",               # Dark background
                "fg": "#f5f5f5",               # Lighter text for better contrast
                "button_bg": "#3c3c40",        # Button background
                "button_fg": "#f5f5f5",        # Lighter button text for better contrast
                "highlight_bg": "#4a6ad4",     # Highlight background (blue)
                "highlight_fg": "#f0f0f0",     # Highlight text
                "entry_bg": "#1d1d21",         # Entry background (darker for better contrast)
                "notebook_bg": "#28282e",      # Notebook background
                "border": "#555555",           # Border color
                "success": "#1e6e1e",          # Success color (dark green)
                "scrollbar": "#4a4a4d"         # Scrollbar color
            }
        }
        
    def apply_theme(self, theme_name):
        """Apply the specified theme to the application."""
        if theme_name not in self.color_schemes:
            theme_name = "light"  # Default to light theme if not found
            
        colors = self.color_schemes[theme_name]
        
        # Configure ttk styles
        self.style.configure("TFrame", background=colors["bg"])
        self.style.configure("TLabel", background=colors["bg"], foreground=colors["fg"])
        
        # Buttons
        self.style.configure("TButton", 
                            background=colors["button_bg"], 
                            foreground=colors["button_fg"],
                            borderwidth=1)
        self.style.map("TButton",
                      background=[('active', colors["highlight_bg"]),
                                  ('pressed', self._lighten_or_darken(colors["highlight_bg"], theme_name))],
                      foreground=[('active', colors["button_fg"]), 
                                  ('pressed', colors["button_fg"]),
                                  ('focus', colors["button_fg"])])
                      
        # Accent button (for primary actions)
        self.style.configure("Accent.TButton", 
                            background=colors["highlight_bg"], 
                            foreground=colors["highlight_fg"])
        self.style.map("Accent.TButton",
                      background=[('active', self._lighten_or_darken(colors["highlight_bg"], theme_name)),
                                  ('pressed', self._lighten_or_darken(colors["highlight_bg"], theme_name))],
                      foreground=[('active', colors["highlight_fg"]),
                                  ('pressed', colors["highlight_fg"]),
                                  ('focus', colors["highlight_fg"])])
        
        # Input controls
        self.style.configure("TCheckbutton", background=colors["bg"], foreground=colors["fg"])
        self.style.configure("TRadiobutton", background=colors["bg"], foreground=colors["fg"])
        self.style.configure("TEntry", background=colors["entry_bg"], foreground=colors["fg"],
                            fieldbackground=colors["entry_bg"])
        self.style.configure("TCombobox", 
                            background=colors["entry_bg"], 
                            foreground=colors["fg"],
                            fieldbackground=colors["entry_bg"])
        self.style.map("TCombobox",
                      fieldbackground=[('readonly', colors["entry_bg"])],
                      background=[('readonly', colors["button_bg"])])
                      
        # Frames and grouping
        self.style.configure("TLabelframe", background=colors["bg"], foreground=colors["fg"])
        self.style.configure("TLabelframe.Label", background=colors["bg"], foreground=colors["fg"])
        
        # Notebook (tabs)
        self.style.configure("TNotebook", background=colors["notebook_bg"])
        self.style.configure("TNotebook.Tab", 
                            background=colors["button_bg"], 
                            foreground=colors["button_fg"],
                            padding=[10, 5])
        self.style.map("TNotebook.Tab",
                      background=[('selected', colors["highlight_bg"])],
                      foreground=[('selected', colors["highlight_fg"])])
                      
        # Progressbar
        self.style.configure("TProgressbar", 
                           background=colors["highlight_bg"],
                           troughcolor=colors["entry_bg"])
                        
        # Special labels
        self.style.configure("Title.TLabel", 
                           background=colors["bg"], 
                           foreground=colors["highlight_bg"],
                           font=("Arial", 18, "bold"))
        self.style.configure("Subtitle.TLabel", 
                           background=colors["bg"], 
                           foreground=colors["fg"],
                           font=("Arial", 12))
        
        # Scale (slider)
        self.style.configure("TScale", 
                           background=colors["bg"],
                           troughcolor=colors["entry_bg"])
                           
        # Scrollbars
        self.style.configure("TScrollbar", 
                           background=colors["scrollbar"],
                           troughcolor=colors["bg"],
                           borderwidth=0,
                           arrowsize=14)
        
        # Configure root window
        self.root.configure(background=colors["bg"])
        
        # Return colors to be used for non-ttk widgets
        return colors
        
    def _lighten_or_darken(self, color, theme):
        """Lighten or darken a color based on the theme."""
        # Convert hex to RGB
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        
        # Lighten or darken based on theme
        if theme == "light":
            # Darken for light theme
            r = max(0, r - 20)
            g = max(0, g - 20)
            b = max(0, b - 20)
        else:
            # Lighten for dark theme
            r = min(255, r + 20)
            g = min(255, g + 20)
            b = min(255, b + 20)
            
        # Convert back to hex
        return f"#{r:02x}{g:02x}{b:02x}"
        
    def configure_text_widget(self, widget, theme_name):
        """Configure a text widget with the theme colors."""
        colors = self.color_schemes[theme_name]
        
        widget.configure(
            background=colors["entry_bg"],
            foreground=colors["fg"],
            insertbackground=colors["fg"],  # Cursor color
            selectbackground=colors["highlight_bg"],
            selectforeground=colors["highlight_fg"],
            relief="flat",
            borderwidth=1,
            highlightbackground=colors["border"],
            highlightcolor=colors["highlight_bg"],
            highlightthickness=1
        )
        
        # Make selected text truly stand out
        if theme_name == "dark":
            widget.config(selectbackground="#ffcc00", selectforeground="#000000")
        else:
            widget.config(selectbackground="#3a5ab4", selectforeground="#f0f0f0")
        
    def flash_success(self, widget, theme_name, duration=200):
        """Flash a widget with success color."""
        colors = self.color_schemes[theme_name]
        original_bg = widget['background']
        
        widget.configure(background=colors["success"])
        self.root.after(duration, lambda: widget.configure(background=original_bg))