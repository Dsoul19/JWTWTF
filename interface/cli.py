from interface.gui import JWTWTFGUI
from core.engine import JWTEngine
from core.logic import JWTLogic
from rich.console import Console
import threading
import sys

class CLI:
    def __init__(self):
        self.logic = JWTLogic()
        self.engine = JWTEngine(self.logic)
        self.console = Console()
        self.running = True
        self.current_technique = None
        self.current_module = None

    def get_prompt(self):
        if self.current_technique:
            if self.current_module:
                return f"[#00ff00]jwtwtf ([/][#00ff00]{self.current_technique}/{self.current_module}[/][#00ff00])[/]"
            return f"[#00ff00]jwtwtf ([/][#00ff00]{self.current_technique}[/][#00ff00])[/]"
        return "[#00ff00]jwtwtf[/]"

    def run(self):
        banner = """                                                                                                                                                                                                                                                                              
                                   ######                
               ###############    #########              
            #######       ###########    ####            
          #####                ######      ######        
         ###                     ####     ###  #####     
        ###                      ####  ###   ###  ###    
       ###                       ####  ## ###  ##   ###   
      ##      ######             ####  ##     ###   ####  
     ###    ##########           ####   #######     #### 
     ##   #### ###  ###    ###    ###               ##### 
    ###   ##  #### ###    ###  ### ##################### 
    ###       ### ####   ###  ###                   #### 
 ###############  #########  ##########################  
 ##           ###  #### ####  #####         ###          
 ##           ####  ####  ####   ####       ###          
 ####################################### #####           
   ###  #######   ####        ######                     
   ###  #########                                        
   ### ###     ###                                       
   ### ####### ###                                       
    ### ##### ####                                       
     ############                                        
       ######## 
                                                                                                                                                                                                                          
      ~===> [bold #00ff00]JWTWTF[/] – [blink italic]WHAT THE FUZZ?![/]
     /     [bold #5fafff]CHAMELEON STRIKE[/]
    /     > [bright_green]snap[/] > [bright_yellow]fuzz[/] > [bright_red]own[/]
   /      ~ coded by [bold #ff5f00]DSoul19[/] A.K.A [bold #ff5f00]Goutam Ku. Jena[/]
    v1.0 - [italic #af87ff]"🦎 Like a chameleon: I blend, I bend, I break, then transcend."[/]
"""

        self.console.print(f"[bold #00ff00]{banner}[/]")
        self.console.print("[bold #ff0000 on black]Type 'help' for commands... or just start fuzzing ( ͡° ͜ʖ ͡°)[/]")
                
        while self.running:
            try:
                # Print styled prompt using rich Console
                self.console.print(f"{self.get_prompt()}> ", end="")
                cmd = input().strip().split()
                if not cmd:
                    continue
                command = cmd[0].lower()
                args = cmd[1:]

                if command == "exit":
                    self.running = False
                    self.console.print("[+] Exiting JWTWTF.")
                # elif command == "gui":
                #     self._launch_gui()
                elif command == "help":
                    self._show_help()
                elif command == "man":
                    self._show_man()
                elif command == "techniques":
                    self._show_techniques()
                elif command == "use":
                    self._use_command(args)
                elif command == "set":
                    self._set_param(args)
                elif command == "add_token":
                    self._add_token(args)
                elif command == "compare":
                    self._compare_tokens(args)
                elif command == "show" and args:
                    if args[0] == "modules":
                        self._show_modules()
                    elif args[0] == "options":
                        self._show_options()
                elif command == "run":
                    self._run_module()
                elif command == "analyze":
                    self._analyze_token()
                elif command == "extract":
                    self._extract_token(args)
                elif command in ["prev", "return", "back"]:
                    self._navigate_back()
                else:
                    self.console.print("[!] Unknown command. Type 'help' for commands.")
            except KeyboardInterrupt:
                self.console.print("\n[!] KeyboardInterrupt detected. Use 'exit' command to quit.")
            except Exception as e:
                self.console.print(f"[!] Error: {str(e)}")

    # def _launch_gui(self):
    #     self.console.print("[+] Launching GUI in a separate thread...")
    #     gui_thread = threading.Thread(target=JWTWTFGUI().run)
    #     gui_thread.start()

    def _show_techniques(self):
        techniques = ["[1] jwt_extractor - Extract JWTs from various sources", "[2] jwt_exploiter - Exploit JWT vulnerabilities"]
        self.console.print("\n".join(techniques))

    def _use_command(self, args):
        if not args:
            self.console.print("[!] Specify a technique or module (e.g., 'use 1', 'use 3')")
            return
        
        target = args[0].lower()
        plugin_names = list(self.engine.plugins.keys())  # List of module names for numeric mapping

        # If no technique is selected, only allow technique selection
        if not self.current_technique:
            if target == "1":
                self.current_technique = "jwt_extractor"
                self.current_module = None
                self.console.print("[+] Using technique: jwt_extractor")
            elif target == "2":
                self.current_technique = "jwt_exploiter"
                self.current_module = None
                self.console.print("[+] Using technique: jwt_exploiter")
            else:
                self.console.print("[!] Select a technique first with 'use 1' or 'use 2'. Use 'techniques' for options.")
            return

        # If inside jwt_exploiter, treat all numeric inputs as module selections
        if self.current_technique == "jwt_exploiter":
            module = None
            try:
                module_idx = int(target) - 1  # Convert to 0-based index
                if 0 <= module_idx < len(plugin_names):
                    module = plugin_names[module_idx]
            except ValueError:
                module = target if target in plugin_names else None

            if module:
                self.engine.use_plugin(module)
                self.current_module = module
                self.console.print(f"[+] Using module: {module}")
            else:
                self.console.print(f"[!] Invalid module: {target}. Use 'show modules' to see available options.")
        # If inside jwt_extractor, allow switching to jwt_exploiter
        elif self.current_technique == "jwt_extractor":
            if target == "2":
                self.current_technique = "jwt_exploiter"
                self.current_module = None
                self.console.print("[+] Using technique: jwt_exploiter")
            elif target == "1":
                self.console.print("[+] Already using technique: jwt_extractor")
            else:
                self.console.print("[!] Use 'use 2' to switch to jwt_exploiter or 'run' to extract.")

    def _set_param(self, args):
        if len(args) < 2:
            self.console.print("[!] Usage: set <param> <value>")
            return
        param, value = args[0], " ".join(args[1:])
        if param == "target":
            self.engine.set_target(value)
            self.console.print(f"[+] Target set to {value}")
        elif param == "proxy":
            self.engine.set_proxy(value)
            self.console.print(f"[+] Proxy set to {value}")
        elif param == "token":
            self.logic.add_token(value)
            self.console.print(f"[+] Token set to {value} (ID: default)")
        elif self.current_module and param in self.engine.current_plugin.options:
            result = self.engine.set_plugin_param(param, value)
            self.console.print(f"[+] {result}")
        elif self.current_technique == "jwt_extractor" and param in ["js", "ws", "api", "all", "ws_duration"]:
            setattr(self.engine.extractor, param, value.lower() in ["true", "yes"] if param != "ws_duration" else int(value))
            self.console.print(f"[+] {param} set to {value}")
        else:
            self.console.print(f"[!] Unknown parameter: {param}")

    def _add_token(self, args):
        if len(args) < 1:
            self.console.print("[!] Usage: add_token <jwt> [id]")
            return
        token = args[0]
        tid = args[1] if len(args) > 1 else f"token_{len(self.logic.tokens)}"
        self.logic.add_token(token, tid)
        self.console.print(f"[+] Added token with ID: {tid}")

    def _compare_tokens(self, args):
        if len(args) != 2:
            self.console.print("[!] Usage: compare <token_id1> <token_id2>")
            return
        result = self.logic.compare_tokens(args[0], args[1])
        self.console.print(f"[*] {result}")

    def _show_modules(self):
        if self.current_technique != "jwt_exploiter":
            self.console.print("[!] Select jwt_exploiter first with 'use 2'")
            return
        modules = [f"[{i+1}] {p}" for i, p in enumerate(self.engine.plugins.keys())]
        self.console.print("\n".join(modules))

    def _show_options(self):
        if self.current_technique == "jwt_extractor":
            options = [
                "Options:",
                "  - target: Target URL to extract from (Required, e.g., http://example.com)",
                "  - js: Include JS files (Optional, default: False, e.g., true)",
                "  - ws: Include WebSocket (Optional, default: False, e.g., true)",
                "  - api: Include API endpoints (Optional, default: False, e.g., true)",
                "  - all: Return all tokens (Optional, default: False, e.g., true)",
                "  - ws_duration: WebSocket listen duration in seconds (Optional, default: 5, e.g., 10)"
            ]
            self.console.print("\n".join(options))
        elif self.current_module:
            plugin = self.engine.current_plugin
            options = ["Options:"]
            for opt, details in plugin.options.items():
                required = "Required" if details["required"] else "Optional"
                default = f", default: {details['default']}" if details.get("default") is not None else ""
                example = f", e.g., {plugin.example_usage[0].split()[-1]}" if plugin.example_usage else ""
                options.append(f"  - {opt}: {details['description']} ({required}{default}{example})")
            self.console.print("\n".join(options))
        else:
            self.console.print("[!] Select a technique or module first with 'use <number>'.")

    def _run_module(self):
        if self.current_technique == "jwt_extractor":
            if not self.engine.extractor.target:
                self.console.print("[!] Missing required option: target")
                return
            result = self.engine.extract_jwt(
                all=getattr(self.engine.extractor, "all", False),
                js=getattr(self.engine.extractor, "js", False),
                ws=getattr(self.engine.extractor, "ws", False),
                api=getattr(self.engine.extractor, "api", False),
                ws_duration=getattr(self.engine.extractor, "ws_duration", 5)
            )
            self.console.print(f"[*] {result}")
        elif self.current_module:
            plugin = self.engine.current_plugin
            missing = [opt for opt, details in plugin.options.items() if details["required"] and not getattr(plugin, opt, None)]
            if missing:
                self.console.print(f"[!] Missing required options: {', '.join(missing)}")
                return
            result = self.engine.run()
            self.console.print(f"[*] {result}")
        else:
            self.console.print("[!] Select a module or technique first.")

    def _analyze_token(self):
        if self.current_technique != "jwt_exploiter":
            self.console.print("[!] Select jwt_exploiter first with 'use 2'")
            return
        result = self.logic.analyze()
        self.console.print(f"[*] {result}")

    def _extract_token(self, args):
        if self.current_technique != "jwt_extractor":
            self.console.print("[!] Select jwt_extractor first with 'use 1'")
            return
        self._run_module()

    def _navigate_back(self):
        if self.current_module:
            self.current_module = None
            self.engine.current_plugin = None
            self.console.print(f"[+] Returned to {self.current_technique}")
        elif self.current_technique:
            self.current_technique = None
            self.console.print("[+] Returned to root")

    def _show_help(self):
        help_text = (
            "[*] Available Commands:\n"
            "gui                       # Launch the graphical user interface\n"
            "techniques                # List available techniques\n"
            "use <1|2>                 # Select technique (1: jwt_extractor, 2: jwt_exploiter)\n"
            "use <name|number>         # Select module inside jwt_exploiter\n"
            "set <param> <value>       # Set a parameter (e.g., target, token)\n"
            "add_token <jwt> [id]      # Add JWT with optional ID\n"
            "compare <id1> <id2>       # Compare two tokens\n"
            "show modules              # List modules (jwt_exploiter only)\n"
            "show options              # Show options for selected module/technique\n"
            "run                       # Execute selected module/technique\n"
            "extract                   # Extract JWTs (jwt_extractor only)\n"
            "analyze                   # Analyze current token\n"
            "prev / return             # Navigate back\n"
            "man                       # Display detailed manual\n"
            "exit                      # Exit"
        )
        self.console.print(help_text)

    def _show_man(self):
        man_text = (
            "[*] JWTWTF Manual - Advanced JWT Exploitation Framework\n"
            "\n[*] Overview:\n"
            "  JWTWTF is a powerful tool for extracting and exploiting JSON Web Tokens (JWTs).\n"
            "  It supports two main techniques: jwt_extractor and jwt_exploiter.\n"
            "\n[*] Workflow:\n"
            "  1. Start by selecting a technique with 'use <1|2>'.\n"
            "  2. For jwt_exploiter, select a module with 'use <number|name>'.\n"
            "  3. Configure options with 'set <param> <value>'.\n"
            "  4. Run the module with 'run' or extract tokens with 'extract'.\n"
            "\n[*] Key Commands:\n"
            "  - gui: Launches the GUI for a visual interface.\n"
            "  - use <1|2>: Switch between techniques.\n"
            "  - use <name|number>: Select modules in jwt_exploiter.\n"
            "  - set: Configure parameters (use 'show options' for module-specific params).\n"
            "  - show modules: List all exploitation modules.\n"
            "  - show options: Display configurable options for the current module.\n"
            "  - run: Execute the selected module.\n"
            "  - extract: Fetch JWTs from a target (jwt_extractor only).\n"
            "\n[*] Example Session:\n"
            "  jwtwtf > use 2\n"
            "  [+] Using technique: jwt_exploiter\n"
            "  jwtwtf (jwt_exploiter) > show modules\n"
            "  jwtwtf (jwt_exploiter) > use 5\n"
            "  [+] Using module: claim_inject\n"
            "  jwtwtf (jwt_exploiter/claim_inject) > show options\n"
            "  jwtwtf (jwt_exploiter/claim_inject) > set payload '{\"admin\": true}'\n"
            "  [+] Set payload to {\"admin\": true}\n"
            "  jwtwtf (jwt_exploiter/claim_inject) > run\n"
            "\n[*] Tips:\n"
            "  - Use 'prev' or 'return' to navigate back.\n"
            "  - Check 'show options' for each module’s requirements.\n"
            "  - Run 'gui' for a visual alternative."
        )
        self.console.print(man_text)

if __name__ == "__main__":
    CLI().run()