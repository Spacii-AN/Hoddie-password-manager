import ttkbootstrap as tb
from ttkbootstrap.constants import *

class ThemeManager:
    """Manages themes and styling using ttkbootstrap."""

    def __init__(self, root, theme_name='flatly'):
        """Initialize with a root window and a ttkbootstrap theme."""
        self.root = root
        self.style = tb.Style(theme_name)  # Set built-in ttkbootstrap theme

        # Color overrides (optional)
        self.colors = {
            "light": {
                "success": "#4cd964",  # Custom success flash
            },
            "dark": {
                "success": "#1e6e1e"
            }
        }

    def apply_theme(self, theme_name='light'):
        """Apply ttkbootstrap theme."""
        self.style.theme_use('flatly' if theme_name == 'light' else 'darkly')
        self.root.configure(background=self.style.colors.bg)
        return self.style.colors

    def configure_text_widget(self, widget, theme_name='light'):
        """Configure a text widget with proper colors for theme."""
        theme_colors = self.style.colors
        widget.configure(
            background=theme_colors.inputbg,
            foreground=theme_colors.text,
            insertbackground=theme_colors.text,
            selectbackground=theme_colors.primary,
            selectforeground=theme_colors.selectfg,
            relief="flat",
            borderwidth=1,
            highlightbackground=theme_colors.border,
            highlightcolor=theme_colors.primary,
            highlightthickness=1
        )

        if theme_name == "dark":
            widget.config(selectbackground="#ffcc00", selectforeground="#000000")
        else:
            widget.config(selectbackground="#3a5ab4", selectforeground="#f0f0f0")

    def flash_success(self, widget, theme_name='light', duration=200):
        """Flash widget with success color for a brief time."""
        flash_color = self.colors[theme_name]["success"]
        original_bg = widget['background']
        widget.configure(background=flash_color)
        self.root.after(duration, lambda: widget.configure(background=original_bg))
