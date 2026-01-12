"""
Plugin loader for dynamically discovering and loading vulnerability modules.
"""

import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict, Type
import sys

from plugins.base_plugin import BasePlugin


class PluginLoader:
    """
    Dynamically discovers and loads vulnerability scanner plugins.
    """
    
    def __init__(self, plugins_dir: str = None):
        """
        Initialize the plugin loader.
        
        Args:
            plugins_dir: Path to plugins directory (defaults to 'plugins/')
        """
        if plugins_dir:
            self.plugins_dir = Path(plugins_dir)
        else:
            self.plugins_dir = Path(__file__).parent.parent / 'plugins'
        
        self.loaded_plugins: Dict[str, BasePlugin] = {}
        self.plugin_classes: Dict[str, Type[BasePlugin]] = {}
    
    def discover_plugins(self) -> List[str]:
        """
        Discover all plugin modules in the plugins directory.
        
        Returns:
            List of plugin module names
        """
        plugin_names = []
        
        # Get the plugins package
        try:
            import plugins
            package_path = Path(plugins.__file__).parent
            
            for _, module_name, is_pkg in pkgutil.iter_modules([str(package_path)]):
                # Skip base_plugin and __init__
                if module_name in ('base_plugin', '__init__'):
                    continue
                
                if not is_pkg:  # Only load modules, not subpackages
                    plugin_names.append(module_name)
        
        except Exception as e:
            print(f"Error discovering plugins: {e}")
        
        return plugin_names
    
    def load_plugin(self, module_name: str) -> BasePlugin:
        """
        Load a single plugin module.
        
        Args:
            module_name: Name of the plugin module (without 'plugins.' prefix)
        
        Returns:
            Instantiated plugin object
        """
        try:
            # Import the module
            full_module_name = f'plugins.{module_name}'
            module = importlib.import_module(full_module_name)
            
            # Find the plugin class (subclass of BasePlugin)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                
                if (isinstance(attr, type) and 
                    issubclass(attr, BasePlugin) and 
                    attr is not BasePlugin):
                    
                    # Instantiate the plugin
                    plugin_instance = attr()
                    self.loaded_plugins[plugin_instance.name] = plugin_instance
                    self.plugin_classes[plugin_instance.name] = attr
                    
                    return plugin_instance
            
            raise ValueError(f"No plugin class found in {module_name}")
        
        except Exception as e:
            print(f"Error loading plugin {module_name}: {e}")
            raise
    
    def load_all_plugins(self) -> List[BasePlugin]:
        """
        Discover and load all plugins.
        
        Returns:
            List of loaded plugin instances
        """
        plugin_names = self.discover_plugins()
        loaded = []
        
        for name in plugin_names:
            try:
                plugin = self.load_plugin(name)
                if plugin:
                    loaded.append(plugin)
                    print(f"Loaded plugin: {plugin.name}")
            except Exception as e:
                print(f"Failed to load {name}: {e}")
        
        return loaded
    
    def get_plugin(self, name: str) -> BasePlugin:
        """Get a loaded plugin by name"""
        return self.loaded_plugins.get(name)
    
    def get_all_plugins(self) -> List[BasePlugin]:
        """Get all loaded plugins"""
        return list(self.loaded_plugins.values())
    
    def get_enabled_plugins(self) -> List[BasePlugin]:
        """Get all enabled plugins"""
        return [p for p in self.loaded_plugins.values() if p.enabled]
    
    def get_plugins_by_owasp(self, category: str) -> List[BasePlugin]:
        """Get plugins by OWASP category"""
        return [p for p in self.loaded_plugins.values() 
                if category in p.owasp_category.value]
    
    def reload_plugin(self, name: str) -> BasePlugin:
        """Reload a specific plugin"""
        # Find the module name
        for plugin_name, plugin in self.loaded_plugins.items():
            if plugin_name == name:
                module_name = plugin.__class__.__module__.split('.')[-1]
                
                # Remove from loaded
                del self.loaded_plugins[name]
                
                # Reload and return
                return self.load_plugin(module_name)
        
        raise ValueError(f"Plugin {name} not found")
    
    def get_plugin_info(self) -> List[Dict]:
        """Get info for all loaded plugins"""
        return [p.get_info() for p in self.loaded_plugins.values()]
