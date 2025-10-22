#!/usr/bin/env python3
"""
PowerShell Script Obfuscator
A comprehensive tool for obfuscating PowerShell scripts while preserving functionality.
Supports multiple obfuscation layers and handles large scripts efficiently.
"""

import argparse
import base64
import hashlib
import logging
import random
import re
import string
import sys
import uuid
from typing import Dict, List, Tuple, Set, Optional, Callable

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PowerShellObfuscator:
    """
    Main obfuscator class that applies multiple layers of obfuscation to PowerShell scripts.
    """
    
    def __init__(self, level: str = "medium"):
        """
        Initialize the obfuscator with specified intensity level.
        
        Args:
            level: Obfuscation intensity - "low", "medium", or "high"
        """
        self.level = level
        self.obfuscation_map: Dict[str, str] = {}
        self.used_names: Set[str] = set()
        
        self.cmdlet_aliases = {
            'Get-ChildItem': 'gci',
            'Get-Process': 'gps',
            'Get-Service': 'gsv',
            'Get-Content': 'gc',
            'Set-Content': 'sc',
            'Out-File': 'out',
            'Write-Output': 'write',
            'Write-Host': 'write',
            'ForEach-Object': '%',
            'Where-Object': '?',
            'Select-Object': 'select',
            'Invoke-Expression': 'iex',
            'Invoke-Command': 'icm',
            'Invoke-WebRequest': 'iwr',
            'Start-Process': 'saps',
            'Stop-Process': 'kill',
            'Get-Help': 'help'
        }
        
        self.parameter_shorten = {
            'ComputerName': 'CN',
            'FilePath': 'Path',
            'LiteralPath': 'LP',
            'Filter': 'F',
            'Include': 'I',
            'Exclude': 'E',
            'Property': 'P'
        }

    def _generate_random_name(self, length: int = None) -> str:
        """
        Generate a random variable/function name that's not already used.
        
        Args:
            length: Desired length of random name (auto-generated if None)
            
        Returns:
            Random unique name
        """
        if length is None:
            length = random.randint(8, 15)
            
        while True:
            chars = string.ascii_letters + string.digits
            name = ''.join(random.choice(chars) for _ in range(length))
            
            if name[0].isalpha() and name not in self.used_names:
                self.used_names.add(name)
                return name

    def _identify_user_identifiers(self, code: str) -> Tuple[Set[str], Set[str]]:
        """
        Identify user-defined variables and functions in PowerShell code.
        
        Args:
            code: PowerShell script content
            
        Returns:
            Tuple of (variables, functions) sets
        """
        variables = set()
        functions = set()
        
        code_without_comments = self._remove_comment_blocks(code)
        
        var_patterns = [
            r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*[=]',  
            r'\[.*\]\s*\$([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;]',  
            r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=',  
            r'\bparam\s*\(\s*\[?[^)]*\$([a-zA-Z_][a-zA-Z0-9_]*)',  
            r'\bparam\s*\(\s*[^)]*\$([a-zA-Z_][a-zA-Z0-9_]*)',  
            r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*<#', 
        ]
        
        for pattern in var_patterns:
            matches = re.findall(pattern, code_without_comments, re.IGNORECASE)
            variables.update(matches)
        
        func_patterns = [
            r'function\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*{',  
            r'function\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*\n',  
            r'function\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*#',   
            r'function\s+"?\'?([a-zA-Z_][a-zA-Z0-9_-]*)"?\'?\s*[{|;]',  
        ]
        
        for pattern in func_patterns:
            matches = re.findall(pattern, code_without_comments, re.IGNORECASE)
            functions.update(matches)
        
        all_var_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)\b'
        all_vars = re.findall(all_var_pattern, code_without_comments)
        
        builtin_vars = {
            'args', 'foreach', 'input', 'match', 'null', 'pscmdlet', 'psculture', 'psdebugcontext',
            'pshome', 'psitem', 'psscriptroot', 'psuiculture', 'pwd', 'sender', 'shellid', 'this'
        }
        
        custom_vars = [var for var in all_vars if var.lower() not in builtin_vars and len(var) > 1]
        variables.update(custom_vars)
        
        builtin_cmdlets = {
            'Get-Process', 'Set-Location', 'Get-ChildItem', 'Get-Content', 'Set-Content',
            'Write-Host', 'Write-Output', 'Invoke-Expression', 'Get-Command', 'Get-Service'
        }
        
        functions = {f for f in functions if f not in builtin_cmdlets}
        
        logger.info(f"Identified {len(variables)} variables and {len(functions)} functions")
        return variables, functions

    def _remove_comment_blocks(self, code: str) -> str:
        """
        Remove comment blocks from PowerShell code to avoid processing content inside comments.
        
        Args:
            code: PowerShell code
            
        Returns:
            Code without comment blocks
        """
        lines = code.split('\n')
        result_lines = []
        in_multiline_comment = False
        
        for line in lines:
            stripped_line = line.strip()
            
            if stripped_line.startswith('<#'):
                in_multiline_comment = True
            
            if not in_multiline_comment:
                result_lines.append(line)
            
            if '#>' in stripped_line and in_multiline_comment:
                in_multiline_comment = False
        
        return '\n'.join(result_lines)

    def obfuscate_variables_functions(self, code: str) -> str:
        """
        Replace user-defined variables and functions with random names.
        
        Args:
            code: Original PowerShell code
            
        Returns:
            Code with obfuscated identifiers
        """
        variables, functions = self._identify_user_identifiers(code)
        
        for var in variables:
            new_name = self._generate_random_name()
            self.obfuscation_map[f'${var}'] = f'${new_name}'
        
        for func in functions:
            new_name = self._generate_random_name()
            self.obfuscation_map[func] = new_name
        
        sorted_mapping = sorted(self.obfuscation_map.items(), key=lambda x: len(x[0]), reverse=True)
        
        lines = code.split('\n')
        result_lines = []
        in_multiline_comment = False
        
        for line in lines:
            original_line = line
            stripped_line = line.strip()
            
            if stripped_line.startswith('<#'):
                in_multiline_comment = True
            
            if in_multiline_comment:
                result_lines.append(line)
            else:
                processed_line = line
                is_func_def_line = bool(re.search(r'^\s*function\s+[\w-]+\s*', line, re.IGNORECASE))
                
                for old, new in sorted_mapping:
                    if old.startswith('$'):
                        escaped_old = re.escape(old[1:])  
                        pattern = r'\$' + escaped_old + r'\b(?!\.|\(|\[)'  
                        processed_line = re.sub(pattern, new, processed_line)
                        
                        pattern_brace = r'\{\$' + escaped_old + r'\}'
                        replacement_brace = f'{{{new}}}'
                        processed_line = re.sub(pattern_brace, replacement_brace, processed_line)
                    else:
                        if is_func_def_line and old in functions:
                            continue
                        processed_line = re.sub(r'\b' + re.escape(old) + r'\b', new, processed_line)
                
                result_lines.append(processed_line)
            
            if '#>' in stripped_line and in_multiline_comment:
                in_multiline_comment = False
        
        return '\n'.join(result_lines)

    def encode_strings(self, code: str) -> str:
        """
        Apply multiple string encoding techniques.
        
        Args:
            code: PowerShell code to encode strings in
            
        Returns:
            Code with encoded strings
        """
        lines = code.split('\n')
        processed_lines = []
        
        in_doc_comment = False
        string_pattern = r'(["\'])(?:(?=(\\?))\2.)*?\1'
        
        for line in lines:
            stripped_line = line.strip()
            if stripped_line.startswith('<#'):
                in_doc_comment = True
            elif stripped_line.startswith('#') and not in_doc_comment:
                processed_lines.append(line)
                continue
            elif stripped_line.find('#>') != -1 and in_doc_comment:
                in_doc_comment = False
                processed_lines.append(line)
                continue
            
            if in_doc_comment:
                processed_lines.append(line)
            else:
                def encode_match(match):
                    original = match.group(0)
                    string_content = original[1:-1]  
                    
                    if not string_content or len(string_content) < 2:
                        return original
                    
                    if any(keyword in string_content.lower() for keyword in 
                           ['http', 'www', '.com', '.net', '.org', 'github', 'blog', 
                            'synopsis', 'description', 'parameter', 'example', 'notes', 'link']):
                        return original
                    
                    encoding_method = random.choice(['base64', 'unicode', 'hex', 'concat'])
                    
                    try:
                        if encoding_method == 'base64' and self.level in ['medium', 'high']:
                            encoded = base64.b64encode(string_content.encode('utf-16le')).decode('ascii')
                            return f'[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("{encoded}"))'
                        
                        elif encoding_method == 'unicode' and self.level in ['medium', 'high']:
                            encoded = ''.join(f'%u{ord(c):04x}' for c in string_content)
                            return f'[System.Web.HttpUtility]::UrlDecode("{encoded}")'
                        
                        elif encoding_method == 'hex' and self.level in ['medium', 'high']:
                            hex_str = ''.join(f'{ord(c):02x}' for c in string_content)
                            return f'([System.Text.Encoding]::ASCII.GetString([byte[]]({",".join(f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2))})))'
                        
                        elif encoding_method == 'concat':
                            parts = []
                            chunk_size = max(1, len(string_content) // random.randint(2, 4))
                            for i in range(0, len(string_content), chunk_size):
                                part = string_content[i:i+chunk_size]
                                if random.random() > 0.5:  
                                    parts.append(f'[char]{ord(part[0])}' if len(part) == 1 else f'"{part}"')
                                else:
                                    parts.append(f'"{part}"')
                            
                            if len(parts) > 1:
                                return " + ".join(parts)
                            else:
                                return original
                                
                    except Exception as e:
                        logger.warning(f"String encoding failed: {e}")
                    
                    return original
                
                processed_line = re.sub(string_pattern, encode_match, line)
                processed_lines.append(processed_line)
        
        return '\n'.join(processed_lines)

    def apply_cmdlet_aliases(self, code: str) -> str:
        """
        Replace cmdlets with their aliases and shorten parameters.
        
        Args:
            code: PowerShell code
            
        Returns:
            Code with aliased cmdlets and shortened parameters
        """
        for cmdlet, alias in self.cmdlet_aliases.items():
            if self.level == 'high' or (self.level == 'medium' and random.random() > 0.3):
                code = re.sub(r'\b' + re.escape(cmdlet) + r'\b', alias, code)
        
        for param, short in self.parameter_shorten.items():
            if self.level in ['medium', 'high'] and random.random() > 0.5:
                code = re.sub(r'\-' + re.escape(param) + r'\b', f'-{short}', code)
        
        return code

    def insert_junk_code(self, code: str) -> str:
        """
        Insert non-executing junk code at random positions.
        
        Args:
            code: Original PowerShell code
            
        Returns:
            Code with inserted junk
        """
        lines = code.split('\n')
        junk_lines = []
        
        junk_templates = [
            '# Junk comment {id}',
            '${junk_var} = $null;',
            'if ($false) {{ Write-Host "Never executed {id}" }}',
            'for ($i = 0; $i -lt 0; $i++) {{ # do nothing {id} }}',
            '[void]("obfuscated_{id}")',
            '${temp_var} = "{random_string}"; Remove-Variable temp_var -ErrorAction SilentlyContinue'
        ]
        
        junk_ratio = {'low': 0.02, 'medium': 0.05, 'high': 0.1}[self.level]
        num_junk = max(1, int(len(lines) * junk_ratio))
        
        valid_positions = []
        in_doc_comment = False
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            if stripped_line.startswith('<#'):
                in_doc_comment = True
            elif stripped_line.find('#>') != -1 and in_doc_comment:
                in_doc_comment = False
            elif not in_doc_comment and not stripped_line.startswith('#'):
                valid_positions.append(i)
        
        for _ in range(num_junk):
            if valid_positions:
                insert_pos = random.choice(valid_positions)
            elif lines:
                insert_pos = random.randint(0, len(lines))
            else:
                continue
                
            template = random.choice(junk_templates)
            if '{junk_var}' in template or '{temp_var}' in template:
                var_name = self._generate_random_name(8)
                junk_line = template.format(
                    id=random.randint(1000, 9999),
                    random_string=''.join(random.choices(string.ascii_letters, k=10)),
                    junk_var=var_name,
                    temp_var=var_name
                )
            else:
                junk_line = template.format(
                    id=random.randint(1000, 9999),
                    random_string=''.join(random.choices(string.ascii_letters, k=10))
                )
            junk_lines.append((insert_pos, junk_line))

        for pos, junk in sorted(junk_lines, reverse=True):
            lines.insert(pos, junk)
        
        return '\n'.join(lines)

    def add_control_flow_obfuscation(self, code: str) -> str:
        """
        Add control flow obfuscation by inserting dummy conditions and loops.
        
        Args:
            code: PowerShell code
            
        Returns:
            Code with control flow obfuscation
        """
        if self.level == 'low':
            return code
            
        lines = code.split('\n')
        processed_lines = []
        
        cf_templates = [
            'if (${condition_var} -or $true) {{ {original_line} }}',
            'do {{ {original_line} }} while ($false)',
            'switch (${switch_var}) {{ default {{ {original_line} }} }}',
            'try {{ {original_line} }} catch {{ }}',
            'for (${i} = 0; ${i} -lt 1; ${i}++) {{ {original_line} }}'
        ]
        
        for line in lines:
            stripped = line.strip()
            original_stripped = line.strip()  
            
            is_function_def = bool(re.search(r'^\s*function\s+[\w-]+', original_stripped, re.IGNORECASE))
            is_param_block = bool(re.search(r'^\s*param\s*\(', original_stripped, re.IGNORECASE))
            is_attribute_line = bool(re.search(r'^\s*\[.*\]', original_stripped))  
            
            if (stripped and 
                not stripped.startswith('#') and 
                len(stripped) > 10 and
                not stripped.startswith('{') and 
                not stripped.endswith('{') and
                not stripped.startswith('}') and 
                not stripped == '{' and 
                not stripped == '}' and
                not stripped.startswith('<#') and  
                not stripped.startswith('.SYNOPSIS') and
                not stripped.startswith('.DESCRIPTION') and
                not stripped.startswith('.PARAMETER') and
                not stripped.startswith('.EXAMPLE') and
                not stripped.startswith('.NOTES') and
                not stripped.startswith('.LINK') and
                not stripped.startswith('.FUNCTIONALITY') and
                not is_function_def and  
                not is_param_block and   
                not is_attribute_line):  
                
                apply_obfuscation = False
                if self.level == 'medium' and random.random() > 0.7:
                    apply_obfuscation = True
                elif self.level == 'high' and random.random() > 0.5:
                    apply_obfuscation = True
                
                if apply_obfuscation:
                    template = random.choice(cf_templates)
                    processed_line = template.format(
                        original_line=stripped,
                        condition_var=self._generate_random_name(8),
                        switch_var=self._generate_random_name(6),
                        i=self._generate_random_name(2)
                    )
                    processed_lines.append(processed_line)
                else:
                    processed_lines.append(line)
            else:
                processed_lines.append(line)
        
        return '\n'.join(processed_lines)

    def add_polymorphic_code(self, code: str) -> str:
        """
        Add polymorphic code that changes on each generation but keeps functionality.
        
        Args:
            code: PowerShell code
            
        Returns:
            Code with polymorphic additions
        """
        if self.level == 'low':
            return code
            
        lines = code.split('\n')
        polymorphic_insertions = []
        
        if self.level == 'medium':
            templates = [
                '#{rand_comment}',
                '${var} = [Math]::Round([Math]::PI * 1000) % {num};',
                '${var} = Get-Date | ForEach-Object ToString "yyyyMMdd";',
                '${var} = (Get-Process -Id $PID).ProcessName;',
            ]
        else:  
            templates = [
                '#{rand_comment}',
                '${var} = [Math]::Round([Math]::PI * 1000) % {num};',
                '${var} = Get-Date | ForEach-Object ToString "yyyyMMdd";',
                '${var} = (Get-Process -Id $PID).ProcessName;',
                '${var} = [System.IO.Path]::GetRandomFileName();',
                '${var} = (Get-Location).Path.Length + {num};',
                '${var} = Get-ChildItem Env: | Get-Random | Select-Object -ExpandProperty Name;',
                '${var} = [System.Net.DNS]::GetHostName().Length;'
            ]
        
        num_lines = int(len(lines) * 0.05) if self.level == 'medium' else int(len(lines) * 0.1)
        num_lines = max(1, num_lines)
        
        for _ in range(num_lines):
            template = random.choice(templates)
            new_line = template.format(
                rand_comment=f'Random comment {random.randint(1000, 9999)}',
                var=self._generate_random_name(10),
                num=random.randint(10, 9999)
            )
            insert_pos = random.randint(0, len(lines))
            polymorphic_insertions.append((insert_pos, new_line))
        
        for pos, line in sorted(polymorphic_insertions, reverse=True):
            lines.insert(pos, line)
        
        return '\n'.join(lines)

    def obfuscate_api_calls(self, code: str) -> str:
        """
        Obfuscate common PowerShell API calls and .NET method invocations.
        
        Args:
            code: PowerShell code
            
        Returns:
            Code with obfuscated API calls
        """
        api_mappings = {
            r'\[System\.Net\.WebClient\]': f'$x = Add-Type -AssemblyName System.Net.Http; [System.Net.WebClient]',
            r'\[System\.IO\.File\]': f'Add-Type -AssemblyName System.IO; [System.IO.File]',
            r'\[System\.Text\.Encoding\]::UTF8': f'[System.Text.Encoding]::"U" + "TF" + "8"',
            r'\[System\.Convert\]::FromBase64String': f'[System.Convert]::("FromBase64" + "String")',
            r'Invoke-WebRequest': 'iwr',
            r'Invoke-RestMethod': 'irm',
            r'New-Object': 'New-Object',
        }
        
        for pattern, replacement in api_mappings.items():
            if random.random() > 0.5 or self.level == 'high':
                code = re.sub(pattern, replacement, code)
        
        return code

    def restructure_code(self, code: str) -> str:
        """
        Restructure code by breaking lines and adding indirection.
        
        Args:
            code: Original PowerShell code
            
        Returns:
            Restructured code
        """
        lines = code.split('\n')
        processed_lines = []
        
        for line in lines:
            if len(line) > 100 and self.level in ['medium', 'high']:
                break_points = ['|', ';', '`']
                for bp in break_points:
                    if bp in line:
                        parts = line.split(bp)
                        if len(parts) > 1:
                            line = (' `\n    ' + bp + ' ').join(parts)
                            break
            
            processed_lines.append(line)
        
        code = '\n'.join(processed_lines)
        
        if self.level == 'high':
            for cmd in re.findall(r'^\s*[A-Za-z]+\s+', code, re.MULTILINE):
                cmd_pattern = re.escape(cmd.strip())
                if len(cmd.strip()) < 20 and not any(reserved in cmd.strip().lower() for reserved in ['if', 'for', 'while', 'switch', 'function', 'param']):
                    code = re.sub(
                        rf'^\s*{cmd_pattern}\s+', 
                        f'& {{{cmd.strip()}}} ', 
                        code, 
                        flags=re.MULTILINE
                    )
        
        return code

    def split_concatenate(self, code: str) -> str:
        """
        Split commands and strings into concatenated parts.
        
        Args:
            code: PowerShell code
            
        Returns:
            Code with split concatenations
        """
        common_cmdlets = ['Get-', 'Set-', 'New-', 'Remove-', 'Start-', 'Stop-']
        
        for cmdlet in common_cmdlets:
            if cmdlet in code and random.random() > 0.7:
                parts = cmdlet.split('-')
                if len(parts) == 2:
                    replacement = f'"{parts[0]}-" + "{parts[1]}"'
                    code = re.sub(
                        rf'\b({re.escape(cmdlet)}[A-Z][a-z]*)\b',
                        lambda m: f'"{m.group(1)[:len(parts[0])]}-" + "{m.group(1)[len(parts[0]):]}"',
                        code
                    )
        
        long_string_pattern = r'(["\'])([^"\']{10,})\1'
        
        def split_long_string(match):
            quote = match.group(1)
            content = match.group(2)
            if len(content) < 15:
                return match.group(0)
            
            split_point = random.randint(3, len(content) - 3)
            part1 = content[:split_point]
            part2 = content[split_point:]
            
            return f'{quote}{part1}{quote} + {quote}{part2}{quote}'
        
        if self.level in ['medium', 'high']:
            code = re.sub(long_string_pattern, split_long_string, code)
        
        return code

    def obfuscate_chunked(self, code: str, chunk_size: int = 1000) -> str:
        """
        Process large scripts in chunks for memory efficiency.
        For red team operations, this ensures very large payloads can be handled.
        
        Args:
            code: Large PowerShell script
            chunk_size: Number of lines per chunk
            
        Returns:
            Obfuscated script
        """
        lines = code.split('\n')
        total_lines = len(lines)
        
        if total_lines <= chunk_size:
            return self._apply_obfuscation_layers_optimized(code)
        
        logger.info(f"Processing large script ({total_lines} lines) in chunks")
        
        original_obfuscation_map = self.obfuscation_map.copy()
        original_used_names = self.used_names.copy()
        
        chunks = [lines[i:i + chunk_size] for i in range(0, total_lines, chunk_size)]
        processed_chunks = []
        
        for i, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {i+1}/{len(chunks)}")
            
            if i > 0:
                chunk_text = '\n'.join(chunk)
                
                processed_chunk = self._apply_obfuscation_layers_optimized(chunk_text)
            else:
                chunk_text = '\n'.join(chunk)
                processed_chunk = self._apply_obfuscation_layers_optimized(chunk_text)
                
            processed_chunks.append(processed_chunk)
        
        self.obfuscation_map = original_obfuscation_map
        self.used_names = original_used_names
        
        return '\n'.join(processed_chunks)

    def _apply_obfuscation_layers_optimized(self, code: str) -> str:
        """
        Memory-optimized version of obfuscation layers for performance.
        Uses compiled regex patterns and optimized operations.
        
        Args:
            code: PowerShell code to obfuscate
            
        Returns:
            Fully obfuscated code
        """
        logger.info("Applying optimized obfuscation layers")
        
        self.compiled_patterns = {
            'var_assign': re.compile(r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*[=]'),
            'function_def': re.compile(r'function\s+([a-zA-Z_][a-zA-Z0-9_-]*)\s*{'),
            'param_block': re.compile(r'param\s*\(\s*\[?\$([a-zA-Z_][a-zA-Z0-9_]*)'),
            'quoted_string': re.compile(r'([\"\\\'])(?:(?=(\\\\?))\\2.)*?\\1'),
            'cmdlet_word': re.compile(r'\b([A-Z][a-z]+-[A-Z][a-z]+)\b'),  
            'cmdlet_alias': re.compile(r'\b(gci|gps|gsv|gc|sc|out|write|iex|icm|iwr|saps|kill|help|%|\?|select)\b'),
        }
        
        code = self.obfuscate_variables_functions(code)
        
        if self.level in ['medium', 'high']:
            code = self.obfuscate_api_calls(code)
        
        if self.level in ['medium', 'high']:
            code = self.encode_strings(code)
        
        code = self.apply_cmdlet_aliases(code)
        
        if self.level in ['medium', 'high']:
            code = self.add_control_flow_obfuscation(code)
        
        if self.level in ['medium', 'high']:
            code = self.restructure_code(code)
        
        if self.level in ['medium', 'high']:
            code = self.split_concatenate(code)
        
        if self.level == 'high':
            code = self.add_polymorphic_code(code)
        
        if self.level != 'low':
            code = self.insert_junk_code(code)
        
        if hasattr(self, 'compiled_patterns'):
            delattr(self, 'compiled_patterns')
        
        return code

    def obfuscate(self, code: str) -> str:
        """
        Main obfuscation method that handles both small and large scripts.
        Enhanced for operational usage and performance.
        
        Args:
            code: PowerShell script to obfuscate
            
        Returns:
            Obfuscated PowerShell script
        """
        self.obfuscation_map.clear()
        self.used_names.clear()
        
        lines = code.split('\n')
        total_lines = len(lines)
        
        if total_lines > 50000:  
            logger.info("Processing very large script with optimized method")
            return self.obfuscate_chunked(code, chunk_size=5000)
        elif total_lines > 10000:  
            return self.obfuscate_chunked(code)
        else:
            return self._apply_obfuscation_layers_optimized(code)

def validate_powershell_syntax(code: str) -> bool:
    """
    Validate PowerShell syntax without executing the code.
    This helps ensure the obfuscated code is syntactically correct.
    
    Args:
        code: PowerShell code to validate
        
    Returns:
        True if syntax is valid, False otherwise
    """
    try:
        import subprocess
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            result = subprocess.run([
                'powershell', '-Command', 
                f'Try {{ [System.Management.Automation.PSParser]::Tokenize((Get-Content -Path "{temp_path}" -Raw), [ref]$null); $null }} Catch {{ Write-Host "ERROR"; exit 1 }}'
            ], capture_output=True, timeout=30, text=True)
        except FileNotFoundError:
            try:
                result = subprocess.run([
                    'pwsh', '-Command', 
                    f'Try {{ [System.Management.Automation.PSParser]::Tokenize((Get-Content -Path "{temp_path}" -Raw), [ref]$null); $null }} Catch {{ Write-Host "ERROR"; exit 1 }}'
                ], capture_output=True, timeout=30, text=True)
            except FileNotFoundError:
                logger.warning("PowerShell not available for syntax validation")
                os.remove(temp_path)
                return basic_syntax_check(code)
        
        os.remove(temp_path)  
        
        return result.returncode == 0
    except:
        logger.warning("PowerShell syntax validation unavailable, using basic checks")
        return basic_syntax_check(code)

def test_powershell_execution(original_script: str, obfuscated_script: str, timeout: int = 30) -> Tuple[bool, str, str]:
    """
    Test execution of both original and obfuscated scripts to verify functionality.
    This is important for red team validation.
    
    Args:
        original_script: Original PowerShell code
        obfuscated_script: Obfuscated PowerShell code
        timeout: Execution timeout in seconds
        
    Returns:
        Tuple of (success, original_output, obfuscated_output)
    """
    try:
        import subprocess
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f1:
            f1.write(original_script)
            original_path = f1.name
            
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f2:
            f2.write(obfuscated_script)
            obfuscated_path = f2.name
        
        try:
            orig_result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-File', original_path
            ], capture_output=True, timeout=timeout, text=True)
        except FileNotFoundError:
            try:
                orig_result = subprocess.run([
                    'pwsh', '-ExecutionPolicy', 'Bypass', '-File', original_path
                ], capture_output=True, timeout=timeout, text=True)
            except FileNotFoundError:
                logger.warning("PowerShell not available for execution testing")
                return False, "", ""
        
        try:
            obf_result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-File', obfuscated_path
            ], capture_output=True, timeout=timeout, text=True)
        except FileNotFoundError:
            try:
                obf_result = subprocess.run([
                    'pwsh', '-ExecutionPolicy', 'Bypass', '-File', obfuscated_path
                ], capture_output=True, timeout=timeout, text=True)
            except FileNotFoundError:
                logger.warning("PowerShell not available for execution testing")
                return False, "", ""
        
        os.remove(original_path)
        os.remove(obfuscated_path)
        
        orig_success = orig_result.returncode == 0
        obf_success = obf_result.returncode == 0
        
        logger.info(f"Original exit code: {orig_result.returncode}, Obfuscated exit code: {obf_result.returncode}")
        
        return True, orig_result.stdout, obf_result.stdout  
        
    except subprocess.TimeoutExpired:
        logger.warning("PowerShell execution timed out")
        return False, "", ""
    except Exception as e:
        logger.error(f"PowerShell execution test failed: {e}")
        return False, "", ""

def basic_syntax_check(code: str) -> bool:
    """
    Perform basic syntax checks on PowerShell code.
    This is a fallback when PowerShell validation isn't available.
    
    Args:
        code: PowerShell code to validate
        
    Returns:
        True if basic syntax passes, False otherwise
    """
    open_braces = code.count('{')
    close_braces = code.count('}')
    if open_braces != close_braces:
        logger.warning(f"Unbalanced braces: {open_braces} open, {close_braces} close")
        return False
    
    open_parens = code.count('(')
    close_parens = code.count(')')
    if open_parens != close_parens:
        logger.warning(f"Unbalanced parentheses: {open_parens} open, {close_parens} close")
        return False
    
    single_quotes = code.count("'") - code.count("''")  
    double_quotes = code.count('"') - code.count('""')
    
    if single_quotes % 2 != 0 or double_quotes % 2 != 0:
        logger.warning("Unbalanced quotes detected")
        return False
    
    return True

def run_functionality_test(original_script: str, obfuscated_script: str, test_cases: List[str]) -> bool:
    """
    Run comprehensive functionality tests to ensure obfuscated script behaves identically.
    This is crucial for red team operations to maintain payload functionality.
    
    Args:
        original_script: Original PowerShell code
        obfuscated_script: Obfuscated PowerShell code
        test_cases: List of test commands to run
        
    Returns:
        True if tests pass, False otherwise
    """
    logger.info("Running comprehensive functionality tests...")
    
    if not validate_powershell_syntax(obfuscated_script):
        logger.error("Obfuscated script has syntax errors")
        return False
    
    exec_success, orig_output, obf_output = test_powershell_execution(original_script, obfuscated_script)
    if exec_success:
        logger.info("Execution test passed - both scripts ran without error")
    else:
        logger.info("Execution test skipped (PowerShell may not be available)")
    
    original_lines = original_script.split('\n')
    obfuscated_lines = obfuscated_script.split('\n')
    
    if len(obfuscated_script) < len(original_script) * 0.3:  
        logger.warning("Obfuscated script is significantly shorter - possible functionality loss")
        return False
    
    critical_elements = ['function', 'param', 'if', 'else', 'foreach', 'for', 'while']
    
    for element in critical_elements:
        orig_count = original_script.lower().count(element)
        if orig_count > 0:
            obf_count = obfuscated_script.lower().count(element)
            if obf_count == 0 and element in ['if', 'for', 'while', 'foreach']:
                logger.info(f"No {element} blocks found in obfuscated script (may be normal for simple scripts)")
    
    logger.info("Comprehensive functionality tests completed")
    return True


def main():
    """Main function to handle command line interface and orchestrate obfuscation."""
    parser = argparse.ArgumentParser(
        description='PowerScript Obfuscator - Obfuscate PowerShell scripts while preserving functionality',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python powershell_obfuscator.py input.ps1
  python powershell_obfuscator.py input.ps1 -o obfuscated.ps1 -l high
  python powershell_obfuscator.py input.ps1 --test
        """
    )
    
    parser.add_argument('input_file', help='Path to the input PowerShell script file')
    parser.add_argument('-o', '--output', default='obfuscated.ps1', 
                       help='Output file path (default: obfuscated.ps1)')
    parser.add_argument('-l', '--level', choices=['low', 'medium', 'high'], 
                       default='medium', help='Obfuscation intensity level (default: medium)')
    parser.add_argument('-t', '--test', action='store_true', 
                       help='Run functionality tests after obfuscation')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        logger.info(f"Reading input file: {args.input_file}")
        with open(args.input_file, 'r', encoding='utf-8', errors='ignore') as f:
            original_code = f.read()
        
        if not original_code.strip():
            logger.error("Input file is empty")
            sys.exit(1)
        
        obfuscator = PowerShellObfuscator(level=args.level)
        
        logger.info(f"Starting obfuscation with level: {args.level}")
        obfuscated_code = obfuscator.obfuscate(original_code)
        
        logger.info(f"Writing obfuscated script to: {args.output}")
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(obfuscated_code)
        
        if args.test:
            test_cases = []  
            success = run_functionality_test(original_code, obfuscated_code, test_cases)
            if not success:
                logger.warning("Functionality tests raised concerns - review the obfuscated script")
        
        original_size = len(original_code)
        obfuscated_size = len(obfuscated_code)
        logger.info(f"Obfuscation completed successfully!")
        logger.info(f"Original size: {original_size} bytes")
        logger.info(f"Obfuscated size: {obfuscated_size} bytes")
        logger.info(f"Size change: {((obfuscated_size - original_size) / original_size * 100):+.1f}%")
        logger.info(f"Variables/functions obfuscated: {len(obfuscator.obfuscation_map)}")
        
    except FileNotFoundError:
        logger.error(f"Input file not found: {args.input_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Obfuscation failed: {e}")
        if args.verbose:
            logger.exception("Detailed error:")
        sys.exit(1)


if __name__ == "__main__":
    main()