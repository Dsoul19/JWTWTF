from plugins import PLUGINS
from extractor import TokenExtractor

class JWTEngine:
    def __init__(self, logic):
        self.logic = logic
        self.plugins = {name: PLUGINS[name](self.logic) for name in PLUGINS.keys()}
        self.current_plugin = None
        self.extractor = TokenExtractor()

    def use_plugin(self, plugin_name):
        if plugin_name in self.plugins:
            self.current_plugin = self.plugins[plugin_name]
            return f"Using module: {plugin_name}"
        return f"Module {plugin_name} not found."

    def run(self):
        if not self.current_plugin:
            return "No module selected."
        return self.current_plugin.run()

    def set_plugin_param(self, param, value):
        if not self.current_plugin:
            return "No module selected."
        return self.current_plugin.set_param(param, value)

    def set_target(self, target):
        self.extractor.target = target

    def set_proxy(self, proxy):
        self.extractor.set_proxy(proxy)

    def extract_jwt(self, all=False, js=False, ws=False, api=False, ws_duration=5):
        return self.extractor.extract(return_all=all, include_js=js, include_ws=ws, include_api=api, ws_duration=ws_duration)