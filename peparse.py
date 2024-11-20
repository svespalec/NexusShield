import re
import pefile
import json
import math
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional


class PEAnalyzer:
    def __init__(
        self,
        patterns_file: str = "iocs/patterns.nex",
        imports_file: str = "iocs/imports.nex",
    ):
        self.patterns = self._load_patterns(patterns_file)
        self.suspicious_functions = self._load_imports(imports_file)

    @staticmethod
    def _load_patterns(file_path: str) -> Dict[str, List[bytes]]:
        try:
            with open(file_path, "r") as f:
                patterns = json.load(f)
                # Convert string patterns to bytes
                return {k: [p.encode() for p in v] for k, v in patterns.items()}
        except Exception as e:
            print(f"Error loading patterns: {e}")
            return {}

    @staticmethod
    def _load_imports(file_path: str) -> Dict[str, List[str]]:
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading imports: {e}")
            return {}

    def get_suspicious_imports(self, pe: pefile.PE) -> List[Dict[str, str]]:
        suspicious_imports = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return suspicious_imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            for imp in entry.imports:
                if not imp.name:
                    continue

                name = imp.name.decode()
                for category, funcs in self.suspicious_functions.items():
                    if any(f.lower() in name.lower() for f in funcs):
                        if not any(x["name"] == name for x in suspicious_imports):
                            suspicious_imports.append(
                                {"name": name, "dll": dll, "category": category}
                            )

        return suspicious_imports

    def get_suspicious_strings(self, data: bytes) -> Dict[str, List[str]]:
        suspicious_strings = {}
        for category, patterns in self.patterns.items():
            matches = set()
            for pattern in patterns:
                escaped_pattern = re.escape(pattern)
                for match in re.finditer(escaped_pattern, data):
                    try:
                        string = match.group().decode("ascii", errors="ignore")
                        matches.add(string)
                    except:
                        continue
            if matches:
                suspicious_strings[category] = list(matches)
        return suspicious_strings

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0

        occurences = [0] * 256
        for byte in data:
            occurences[byte] += 1

        entropy = 0
        for count in occurences:
            if count:
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
        return round(entropy, 2)

    def analyze_pe_file(self, file_path: str) -> Dict[str, Any]:
        try:
            pe = pefile.PE(file_path)
            with open(file_path, "rb") as f:
                data = f.read()

            analysis = {
                "file_info": self._get_file_info(data, pe),
                "suspicious_imports": self.get_suspicious_imports(pe),
                "suspicious_strings": self.get_suspicious_strings(data),
                "high_entropy_sections": self._get_high_entropy_sections(pe),
                "headers": self._get_headers_info(pe),
                "section_info": self._get_section_info(pe),
                "anomalies": self._get_anomalies(pe, data),
                # Additional analysis
                "imports_count": (
                    len(pe.DIRECTORY_ENTRY_IMPORT)
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
                    else 0
                ),
                "exports_count": (
                    len(pe.DIRECTORY_ENTRY_EXPORT.exports)
                    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
                    else 0
                ),
                "is_dll": pe.FILE_HEADER.Characteristics & 0x2000,
                "is_system": pe.FILE_HEADER.Characteristics & 0x1000,
            }

            return analysis
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def _get_file_info(self, data: bytes, pe: pefile.PE) -> Dict[str, Any]:
        return {
            "size": len(data),
            "type": (
                "PE32+"
                if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
                else "PE32"
            ),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "imphash": pe.get_imphash(),
            },
        }

    def _get_high_entropy_sections(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        high_entropy_sections = []
        for section in pe.sections:
            entropy = self.calculate_entropy(section.get_data())
            if entropy > 7.0:
                high_entropy_sections.append(
                    {"name": section.Name.decode().rstrip("\x00"), "entropy": entropy}
                )
        return high_entropy_sections

    @staticmethod
    def _get_headers_info(pe: pefile.PE) -> Dict[str, Any]:
        return {
            "characteristics": pe.FILE_HEADER.Characteristics,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "machine": pe.FILE_HEADER.Machine,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "checksum": pe.OPTIONAL_HEADER.CheckSum,
            "linker_version": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
        }

    def _get_section_info(self, pe: pefile.PE) -> Dict[str, Any]:
        return {
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "sections": [
                {
                    "name": section.Name.decode().rstrip("\x00"),
                    "characteristics": section.Characteristics,
                    "entropy": self.calculate_entropy(section.get_data()),
                    "is_executable": bool(section.Characteristics & 0x20000000),
                    "is_writable": bool(section.Characteristics & 0x80000000),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                }
                for section in pe.sections
            ],
        }

    @staticmethod
    def _get_anomalies(pe: pefile.PE, data: bytes) -> Dict[str, bool]:
        return {
            "has_overlay": len(data)
            > pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData,
            "has_tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
            "has_resources": hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"),
            "has_debug": hasattr(pe, "DIRECTORY_ENTRY_DEBUG"),
            "has_relocations": hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"),
            "has_rich_header": hasattr(pe, "RICH_HEADER"),
            "has_authenticode": bool(
                pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                ].VirtualAddress
            ),
        }


def main():
    import sys

    if len(sys.argv) != 2:
        print("Usage: python pe_analyzer.py <file_path>")
        return

    file_path = sys.argv[1]
    if not Path(file_path).exists():
        print(f"Error: File {file_path} not found")
        return

    analyzer = PEAnalyzer()
    analysis = analyzer.analyze_pe_file(file_path)
    print(json.dumps(analysis, indent=2))


if __name__ == "__main__":
    main()