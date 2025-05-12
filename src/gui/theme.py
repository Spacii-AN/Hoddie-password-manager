import logging
import ttkbootstrap as tb
from ttkbootstrap.constants import *

logger = logging.getLogger(__name__)

class ThemeManager:
    """Manages themes and styling using ttkbootstrap."""

    def __init__(self, root, theme_name='morph'):
        """Initialize with a root window and a ttkbootstrap theme.
        
        Args:
            root: The root window to apply themes to
            theme_name: The initial theme to use (default: 'morph')
        """
        self.root = root
        try:
            self.style = tb.Style(theme_name)  # Set built-in ttkbootstrap theme
        except Exception as e:
            logger.error(f"Failed to initialize theme: {e}")
            self.style = tb.Style('morph')  # Fallback to default theme

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
        """Apply ttkbootstrap theme.
        
        Args:
            theme_name: The theme to apply ('light' or 'dark')
            
        Returns:
            dict: The theme colors
        """
        try:
            theme = 'morph' if theme_name == 'light' else 'superhero'
            self.style.theme_use(theme)
            self.root.configure(background=self.style.colors.bg)
            logger.info(f"Applied theme: {theme}")
            return self.style.colors
        except Exception as e:
            logger.error(f"Failed to apply theme: {e}")
            return self.style.colors

    def configure_text_widget(self, widget, theme_name='light'):
        """Configure a text widget with proper colors for theme.
        
        Args:
            widget: The text widget to configure
            theme_name: The current theme ('light' or 'dark')
        """
        try:
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
        except Exception as e:
            logger.error(f"Failed to configure text widget: {e}")

    def flash_success(self, widget, theme_name='light', duration=200):
        """Flash widget with success color for a brief time.
        
        Args:
            widget: The widget to flash
            theme_name: The current theme ('light' or 'dark')
            duration: How long to flash in milliseconds
        """
        try:
            flash_color = self.colors[theme_name]["success"]
            original_bg = widget['background']
            widget.configure(background=flash_color)
            self.root.after(duration, lambda: widget.configure(background=original_bg))
        except Exception as e:
            logger.error(f"Failed to flash widget: {e}")
