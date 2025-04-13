
# JWTWTF 🦎 - WHAT THE FUZZ?!

![JWTWTF Banner](https://img.shields.io/badge/JWTWTF-v1.0-brightgreen)  
*A Python-powered chameleon that snaps, fuzzes, and owns JSON Web Tokens with cyberpunk swagger.*

---

**JWTWTF** is a slick, dual-mode tool for shredding JSON Web Tokens (JWTs) like a neon phantom in a digital jungle. Built for pentesters and bug hunters, it extracts JWTs from URLs, APIs, WebSockets, or exploits their flaws with lethal precision. Rock the glowing CLI or switch to the GUI for a visual strike—**JWTWTF v1.0** blends, bends, and breaks, begging for your hacks.  

*“Like a chameleon: I blend, I bend, I break, then transcend.”* 😎

---

## ✨ Features

- **JWT Extraction**: Snag tokens from websites, JS files, APIs, or WebSockets.
- **JWT Exploitation**: Crack signatures, inject claims, exploit misconfigs.
- **Neon CLI**: Green prompts (`jwtwtf>`) and ASCII art dripping with hacker vibes.
- **Sleek GUI**: Visualize your JWT chaos with a `--gui` toggle.
- **Modular Core**: Extend it, tweak it—modules for every JWT trick.
- **Cross-Platform**: Windows, macOS, Linux.
- **MIT License**: Free to fork, fix, and flex.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- `pip` for dependencies

### Installation
1. Clone the repo:
   ```bash
   git clone https://github.com/Dsoul19/JWTWTF.git
   cd JWTWTF
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Includes `rich`, `requests`, etc.—see `requirements.txt`.*

### Run It
- **CLI Mode**:
   ```bash
   python jwtwtf.py
   ```
- **GUI Mode**:
   ```bash
   python jwtwtf.py --gui
   ```

CLI output:
```
     ######## 

      ~===> JWTWTF – WHAT THE FUZZ?! (green + magenta)
     /     CHAMELEON STRIKE (cyan)
    /     > snap > fuzz > own (green, yellow, red)
   /      ~ coded by DSoul19 A.K.A Goutam Ku. Jena (orange)
    v1.0 - "🦎 Like a chameleon: I blend, I bend, I break, then transcend." (cyan)

Type 'help' for commands... or just start fuzzing ( ͡° ͜ʖ ͡°) (red on black)
jwtwtf> (bright green)
```

---

## 🛠️ Usage (CLI)

Hack JWTs with these commands:

1. **List Techniques**:
   ```bash
   jwtwtf> techniques
   [1] jwt_extractor - Extract JWTs from various sources
   [2] jwt_exploiter - Exploit JWT vulnerabilities
   ```

2. **Extract JWTs**:
   ```bash
   jwtwtf> use 1
   jwtwtf (jwt_extractor)> set target http://example.com
   jwtwtf (jwt_extractor)> set js true
   jwtwtf (jwt_extractor)> run
   ```

3. **Exploit a Token**:
   ```bash
   jwtwtf> use 2
   jwtwtf (jwt_exploiter)> show modules
   [1] claim_inject
   [2] sig_none
   jwtwtf (jwt_exploiter)> use 1
   jwtwtf (jwt_exploiter/claim_inject)> set payload '{"admin": true}'
   jwtwtf (jwt_exploiter/claim_inject)> run
   ```

4. **Need Help?**:
   ```bash
   jwtwtf> help
   ```
   Or dive deeper:
   ```bash
   jwtwtf> man
   ```

*GUI usage varies—check the interface for point-and-click fuzzing!*

---

## 📂 Project Structure

```
JWTWTF/
├── jwtwtf.py       # Main script (CLI + GUI)
├── core/          # Engine and logic for JWT magic
├── plugins/       # Exploitation modules
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🤝 Contributing

**JWTWTF v1.0** is the opening shot! Got a module, fix, or wild idea?  
- Fork it, hack it, PR it: [GitHub Issues](https://github.com/Dsoul19/JWTWTF/issues).
- Join the fuzz—let’s make JWTs quake!

---

## ⚠️ Ethical Use

Use **JWTWTF** only on systems you’re authorized to test. Unauthorized tinkering is a no-go—keep it legal, keep it chill. 😎

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 💻 Coded By

**Dsoul19** (Goutam Kumar Jena)  
- GitHub: [Dsoul19](https://github.com/Dsoul19)  
- Fuel: Chai, code, and cyberpunk beats.

*“Snap, fuzz, own—JWTWTF’s here to dethrone.”*  
Star the repo, join the hunt, and let’s break some tokens! 🌌

#Cybersecurity #Pentesting #JWT #Python #OpenSource
```