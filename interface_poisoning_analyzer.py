#!/usr/bin/env python3
"""
Interface Poisoning Analyzer
============================
Bu script Java projelerindeki interface'leri analiz ederek
Interface Poisoning Index (IPI) hesaplar.

Kullanım:
    python interface_poisoning_analyzer.py /path/to/java/project

Gereksinimler:
    pip install javalang
"""

import os
import sys
import re
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

try:
    import javalang
except ImportError:
    print("Hata: 'javalang' kütüphanesi gerekli.")
    print("Kurulum: pip install javalang")
    sys.exit(1)


@dataclass
class InterfaceInfo:
    """Bir interface hakkındaki tüm bilgileri tutar"""
    name: str
    file_path: str
    methods: List[str] = field(default_factory=list)
    implementations: List[str] = field(default_factory=list)
    usages: List[str] = field(default_factory=list)  # Bu interface'i kullanan classlar
    method_calls: Dict[str, int] = field(default_factory=dict)  # Her metodun çağrılma sayısı
    extends: List[str] = field(default_factory=list)  # Extend ettiği interface'ler


@dataclass 
class AnalysisResult:
    """Analiz sonuçlarını tutar"""
    interfaces: Dict[str, InterfaceInfo] = field(default_factory=dict)
    classes: Dict[str, dict] = field(default_factory=dict)
    total_classes: int = 0
    call_graph: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))


class InterfacePoisoningAnalyzer:
    """Java projelerinde Interface Poisoning analizi yapar"""
    
    # IPI Ağırlıkları (Navigation-Focused)
    ALPHA = 0.25  # SIR - Single Implementation Risk
    BETA = 0.15   # UUR - Usage Utilization Rate  
    GAMMA = 0.25  # UMR - Unused Method Rate
    DELTA = 0.35  # NCD - Normalized Call Depth
    
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.result = AnalysisResult()
        self.max_call_depth = 1
        
    def analyze(self) -> AnalysisResult:
        """Ana analiz fonksiyonu"""
        print(f"Analiz başlıyor: {self.project_path}")
        
        # 1. Tüm Java dosyalarını bul
        java_files = self._find_java_files()
        print(f"  {len(java_files)} Java dosyası bulundu")
        
        # 2. Her dosyayı parse et
        for file_path in java_files:
            self._parse_file(file_path)
        
        print(f"  {len(self.result.interfaces)} interface bulundu")
        print(f"  {len(self.result.classes)} class bulundu")
        
        # 3. Implementation ilişkilerini bul
        self._find_implementations()
        
        # 4. Usage ilişkilerini bul
        self._find_usages()
        
        # 5. Method çağrılarını analiz et
        self._analyze_method_calls()
        
        # 6. Call depth hesapla
        self._calculate_call_depths()
        
        self.result.total_classes = len(self.result.classes)
        
        return self.result
    
    def _find_java_files(self) -> List[str]:
        """Projedeki tüm .java dosyalarını bulur"""
        java_files = []
        for root, dirs, files in os.walk(self.project_path):
            # Test dosyalarını atla
            if 'test' in root.lower():
                continue
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))
        return java_files
    
    def _parse_file(self, file_path: str):
        """Tek bir Java dosyasını parse eder"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            tree = javalang.parse.parse(content)
            
            for _, node in tree.filter(javalang.tree.InterfaceDeclaration):
                self._process_interface(node, file_path)
            
            for _, node in tree.filter(javalang.tree.ClassDeclaration):
                self._process_class(node, file_path, content)
                
        except Exception as e:
            print(f"  Uyarı: {file_path} parse edilemedi: {e}")
    
    def _process_interface(self, node, file_path: str):
        """Interface node'unu işler"""
        info = InterfaceInfo(
            name=node.name,
            file_path=file_path
        )
        
        # Metodları topla
        if node.methods:
            for method in node.methods:
                info.methods.append(method.name)
                info.method_calls[method.name] = 0
        
        # Extend edilen interface'leri topla
        if node.extends:
            for ext in node.extends:
                if hasattr(ext, 'name'):
                    info.extends.append(ext.name)
        
        self.result.interfaces[node.name] = info
    
    def _process_class(self, node, file_path: str, content: str):
        """Class node'unu işler"""
        class_info = {
            'name': node.name,
            'file_path': file_path,
            'implements': [],
            'extends': None,
            'methods': [],
            'method_calls': []
        }
        
        # Implement edilen interface'leri topla
        if node.implements:
            for impl in node.implements:
                if hasattr(impl, 'name'):
                    class_info['implements'].append(impl.name)
        
        # Extend edilen class'ı topla
        if node.extends:
            if hasattr(node.extends, 'name'):
                class_info['extends'] = node.extends.name
        
        # Metodları topla
        if node.methods:
            for method in node.methods:
                class_info['methods'].append(method.name)
        
        self.result.classes[node.name] = class_info
    
    def _find_implementations(self):
        """Her interface için implement eden class'ları bulur"""
        for class_name, class_info in self.result.classes.items():
            for iface_name in class_info['implements']:
                if iface_name in self.result.interfaces:
                    self.result.interfaces[iface_name].implementations.append(class_name)
    
    def _find_usages(self):
        """Her interface'in kullanıldığı yerleri bulur"""
        for class_name, class_info in self.result.classes.items():
            file_path = class_info['file_path']
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for iface_name in self.result.interfaces:
                    # Field declaration, parameter, return type olarak kullanım
                    patterns = [
                        rf'\b{iface_name}\s+\w+',  # Type declaration
                        rf'<{iface_name}>',        # Generic type
                        rf'\({iface_name}\s+',     # Parameter
                    ]
                    for pattern in patterns:
                        if re.search(pattern, content):
                            if class_name not in self.result.interfaces[iface_name].usages:
                                self.result.interfaces[iface_name].usages.append(class_name)
                            break
            except Exception:
                pass
    
    def _analyze_method_calls(self):
        """Interface metodlarının çağrılma sayısını analiz eder"""
        for class_name, class_info in self.result.classes.items():
            try:
                with open(class_info['file_path'], 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for iface_name, iface_info in self.result.interfaces.items():
                    for method_name in iface_info.methods:
                        # Basit regex ile method çağrısı say
                        pattern = rf'\.{method_name}\s*\('
                        matches = re.findall(pattern, content)
                        iface_info.method_calls[method_name] += len(matches)
            except Exception:
                pass
    
    def _calculate_call_depths(self):
        """Her interface için call depth hesaplar"""
        # Interface inheritance chain derinliğini hesapla
        for iface_name, iface_info in self.result.interfaces.items():
            depth = self._get_interface_depth(iface_name, set())
            if depth > self.max_call_depth:
                self.max_call_depth = depth
    
    def _get_interface_depth(self, iface_name: str, visited: Set[str]) -> int:
        """Recursive olarak interface depth hesaplar"""
        if iface_name in visited:
            return 0
        if iface_name not in self.result.interfaces:
            return 1
        
        visited.add(iface_name)
        iface_info = self.result.interfaces[iface_name]
        
        if not iface_info.extends:
            return 1
        
        max_depth = 0
        for parent in iface_info.extends:
            depth = self._get_interface_depth(parent, visited)
            max_depth = max(max_depth, depth)
        
        return max_depth + 1
    
    def calculate_ipi(self, interface_name: str) -> dict:
        """Tek bir interface için IPI hesaplar"""
        if interface_name not in self.result.interfaces:
            return None
        
        iface = self.result.interfaces[interface_name]
        
        # SIR - Single Implementation Risk
        ic = len(iface.implementations)
        sir = 1.0 / ic if ic > 0 else 1.0
        
        # UUR - Usage Utilization Rate
        iu = len(iface.usages)
        total_classes = max(self.result.total_classes, 1)
        uur = iu / total_classes
        
        # UMR - Unused Method Rate
        total_methods = len(iface.methods)
        if total_methods > 0:
            unused_methods = sum(1 for m, count in iface.method_calls.items() if count == 0)
            umr = unused_methods / total_methods
        else:
            umr = 0.0
        
        # NCD - Normalized Call Depth
        cd = self._get_interface_depth(interface_name, set())
        if self.max_call_depth > 1:
            ncd = (cd - 1) / (self.max_call_depth - 1)
        else:
            ncd = 0.0
        
        # IPI Hesaplama
        ipi = (
            self.ALPHA * sir +
            self.BETA * (1 - uur) +
            self.GAMMA * umr +
            self.DELTA * ncd
        )
        
        return {
            'interface': interface_name,
            'IC': ic,
            'SIR': round(sir, 3),
            'IU': iu,
            'UUR': round(uur, 3),
            'total_methods': total_methods,
            'unused_methods': sum(1 for m, count in iface.method_calls.items() if count == 0),
            'UMR': round(umr, 3),
            'CallDepth': cd,
            'NCD': round(ncd, 3),
            'IPI': round(ipi, 3)
        }
    
    def generate_report(self) -> str:
        """Tüm interface'ler için rapor üretir"""
        lines = []
        lines.append("=" * 70)
        lines.append("INTERFACE POISONING ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"\nProject: {self.project_path}")
        lines.append(f"Total Classes: {self.result.total_classes}")
        lines.append(f"Total Interfaces: {len(self.result.interfaces)}")
        lines.append(f"Max Call Depth: {self.max_call_depth}")
        lines.append("\n" + "-" * 70)
        lines.append("IPI WEIGHTS:")
        lines.append(f"  α (SIR): {self.ALPHA}")
        lines.append(f"  β (UUR): {self.BETA}")
        lines.append(f"  γ (UMR): {self.GAMMA}")
        lines.append(f"  δ (NCD): {self.DELTA}")
        lines.append("-" * 70)
        
        # Her interface için IPI hesapla
        results = []
        for iface_name in self.result.interfaces:
            ipi_result = self.calculate_ipi(iface_name)
            if ipi_result:
                results.append(ipi_result)
        
        # IPI'ya göre sırala (yüksekten düşüğe)
        results.sort(key=lambda x: x['IPI'], reverse=True)
        
        lines.append("\n" + "=" * 70)
        lines.append("INTERFACE POISONING INDEX (IPI) RESULTS")
        lines.append("=" * 70)
        lines.append(f"\n{'Interface':<30} {'IC':>4} {'SIR':>6} {'IU':>4} {'UUR':>6} {'UMR':>6} {'CD':>4} {'NCD':>6} {'IPI':>7}")
        lines.append("-" * 70)
        
        for r in results:
            lines.append(
                f"{r['interface']:<30} {r['IC']:>4} {r['SIR']:>6.3f} {r['IU']:>4} "
                f"{r['UUR']:>6.3f} {r['UMR']:>6.3f} {r['CallDepth']:>4} {r['NCD']:>6.3f} {r['IPI']:>7.3f}"
            )
        
        lines.append("-" * 70)
        
        # İstatistikler
        if results:
            avg_ipi = sum(r['IPI'] for r in results) / len(results)
            max_ipi = max(r['IPI'] for r in results)
            min_ipi = min(r['IPI'] for r in results)
            
            single_impl = sum(1 for r in results if r['IC'] == 1)
            zero_usage = sum(1 for r in results if r['IU'] == 0)
            
            lines.append("\nSUMMARY STATISTICS:")
            lines.append(f"  Average IPI: {avg_ipi:.3f}")
            lines.append(f"  Max IPI: {max_ipi:.3f}")
            lines.append(f"  Min IPI: {min_ipi:.3f}")
            lines.append(f"  Single-Implementation Interfaces: {single_impl} ({100*single_impl/len(results):.1f}%)")
            lines.append(f"  Zero-Usage Interfaces: {zero_usage} ({100*zero_usage/len(results):.1f}%)")
        
        lines.append("\n" + "=" * 70)
        
        # Poisoning seviyeleri
        lines.append("\nPOISONING LEVELS:")
        lines.append("  HIGH (IPI > 0.7):   Immediate refactoring recommended")
        lines.append("  MEDIUM (0.4-0.7):   Review and consider simplification")
        lines.append("  LOW (IPI < 0.4):    Acceptable complexity level")
        
        high = [r for r in results if r['IPI'] > 0.7]
        medium = [r for r in results if 0.4 <= r['IPI'] <= 0.7]
        low = [r for r in results if r['IPI'] < 0.4]
        
        lines.append(f"\n  HIGH:   {len(high)} interfaces")
        lines.append(f"  MEDIUM: {len(medium)} interfaces")
        lines.append(f"  LOW:    {len(low)} interfaces")
        
        if high:
            lines.append("\n  High-risk interfaces:")
            for r in high[:5]:
                lines.append(f"    - {r['interface']} (IPI: {r['IPI']:.3f})")
        
        lines.append("\n" + "=" * 70)
        
        return "\n".join(lines)
    
    def export_json(self, output_path: str):
        """Sonuçları JSON olarak export eder"""
        results = []
        for iface_name in self.result.interfaces:
            ipi_result = self.calculate_ipi(iface_name)
            if ipi_result:
                results.append(ipi_result)
        
        data = {
            'project': self.project_path,
            'total_classes': self.result.total_classes,
            'total_interfaces': len(self.result.interfaces),
            'weights': {
                'alpha_SIR': self.ALPHA,
                'beta_UUR': self.BETA,
                'gamma_UMR': self.GAMMA,
                'delta_NCD': self.DELTA
            },
            'results': results
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"JSON exported to: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Kullanım: python interface_poisoning_analyzer.py /path/to/java/project")
        print("\nÖrnek:")
        print("  python interface_poisoning_analyzer.py ./commons-cli")
        sys.exit(1)
    
    project_path = sys.argv[1]
    
    if not os.path.exists(project_path):
        print(f"Hata: Dizin bulunamadı: {project_path}")
        sys.exit(1)
    
    analyzer = InterfacePoisoningAnalyzer(project_path)
    analyzer.analyze()
    
    report = analyzer.generate_report()
    print(report)
    
    # JSON export
    json_path = os.path.join(os.getcwd(), "ipi_results.json")
    analyzer.export_json(json_path)


if __name__ == "__main__":
    main()
