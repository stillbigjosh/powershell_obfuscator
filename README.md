# PowerShell Obfuscator

A comprehensive PowerShell script obfuscator designed for red team operations. This tool applies multiple layers of obfuscation to PowerShell scripts while preserving their functionality.

### Obfuscation Techniques
- Replaces all user-defined identifiers with randomized names
- Applies various encoding methods including:
  - Base64 encoding with .NET method calls
  - Unicode escape sequences (%u00XX format)
  - Hexadecimal encoding
  - ASCII byte array representations
- **Control Flow Obfuscation**: 
  - Inserts dummy conditional statements (`if`, `switch`, `for` loops)
  - Adds try-catch blocks throughout code
  - Implements do-while constructs that execute once
- Replaces standard cmdlets with shorter aliases (e.g., `Get-Process` → `gps`)
- Adds random variable assignments that don't affect functionality
- Non-executing code to increase entropy and evade signature detection

### Capabilities
- Processes large scripts in chunks for memory optimization
- Works on both Windows PowerShell and PowerShell Core
- Built-in PowerShell syntax checking capabilities
- Verifies obfuscated scripts maintain original behavior
- Three levels (low, medium, high) for tailored obfuscation


## Limitations
1. Highly obfuscated output is larger than original
2. Medium and High obfuscation level can be unreliable (Low is recommended)
3. May not handle all PowerShell language constructs perfectly

## Usage
```bash
python3 powershell_obfuscator.py input.ps1 -o obfuscated.ps1 -l low
```

Options:
- `-l, --level`: Obfuscation intensity (low, medium, high)
- `-t, --test`: Run functionality tests after obfuscation
- `-v, --verbose`: Enable verbose logging

## Disclaimer
Users are responsible for ensuring their use of this tool complies with laws, regulations, and corporate policies. The author cannot be held responsible for any malicious utilizations. The Software is intended exclusively for authorised penetration testers and security researchers who have obtained authorisation from the owner of each target system.
By downloading this software you are accepting the terms of use and the licensing agreement.

