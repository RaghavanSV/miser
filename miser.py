import os
import sys
import shutil
import time
import angr
from scanner import YaraScanner
from refactor_engine import RefactorEngine
from patcher import Patcher
from langchain_aws import ChatBedrockConverse
from langchain_core.messages import HumanMessage, SystemMessage

llm = ChatBedrockConverse(
    model_id="openai.gpt-oss-120b-1:0",
    region_name="us-east-1",
    temperature=1.0,
)

class Miser:
    def __init__(self, target_path, rules_dir="rules"):
        self.target_path = target_path
        self.rules_dir = rules_dir
        
        self.project = angr.Project(target_path, auto_load_libs=False)
        self.arch = self.project.arch.name
        if "AMD64" in self.arch:
            self.arch_simple = "x64"
        else:
            self.arch_simple = "x86"

        self.scanner = YaraScanner(rules_dir)
        self.llm = llm
        self.engine = RefactorEngine(self.arch_simple, llm)
        self.variants_dir = "variants"
        
        if not os.path.exists(self.variants_dir):
            os.makedirs(self.variants_dir)

    def get_segment_info(self, offset):
        """
        Converts file offset to VA and checks if it's in an executable segment.
        Returns [seg_start_va, seg_end_va, byte_va, seg_start_offset, seg_end_offset] if executable, else False.
        """
        main_obj = self.project.loader.main_object
        addr = main_obj.offset_to_addr(offset)
        
        # Find segment containing the address
        seg = main_obj.find_segment_containing(addr)
        if not seg:
            seg = main_obj.find_section_containing(addr)
            
        if seg and seg.is_executable:
            start_va = getattr(seg, 'vaddr', getattr(seg, 'min_addr', 0))
            size = getattr(seg, 'memsize', getattr(seg, 'vsize', 0))
            end_va = start_va + size
            
            start_offset = main_obj.addr_to_offset(start_va)
            if start_offset is None:
                start_offset = 0 # Fallback
            
            end_offset = main_obj.addr_to_offset(end_va - 1)
            if end_offset is None:
                end_offset = len(self.project.loader.main_object.binary)
            else:
                end_offset += 1
            
            return [start_va, end_va, addr, start_offset, end_offset]
        
        return False

    def run_evasion_loop(self, max_iterations=5):
        """Main loop that scans, refactors, and patches until clean."""
        current_file = self.target_path
        print(f"[*] Starting Miser evasion loop for: {current_file}")
        
        for i in range(max_iterations):
            print(f"\n[+] --- Iteration {i+1} ---")
            hits = self.scanner.scan_file(current_file)
            
            if not hits:
                print("[!] Success! No detections found.")
                return current_file
            
            print(f"[*] Found {len(hits)} detections.")
            
            variant_name = f"miser_v{i+1}_{os.path.basename(self.target_path)}"
            variant_path = os.path.join(self.variants_dir, variant_name)
            shutil.copy(current_file, variant_path)
            
            proj = angr.Project(variant_path, auto_load_libs=False)
            patcher = Patcher(variant_path, proj)
            
            with open(variant_path, "rb") as f:
                binary_data = f.read()
            
            applied_any = False
            for hit in hits:
                offset = hit['offset'] # bytes starting address in disk
                length = hit['length']
                rule_name = hit['rule']
                
                seg_info = self.get_segment_info(offset)
                if not seg_info:
                    print(f"[*] Detected bytes at {hex(offset)} are not in an executable segment. Skipping...")
                    continue
                
                seg_start_va, seg_end_va, byte_va, seg_start_offset, seg_end_offset = seg_info
                
                if not self.engine.is_valid_block(binary_data, offset, length):
                    print(f"[*] Detected bytes at {hex(offset)} are not valid instructions. Skipping...")
                    continue
                
                print(f"[*] Refactoring [{rule_name}] at offset {hex(offset)} (VA: {hex(byte_va)})...")
                
                new_asm_content, audit = self.engine.refactor(binary_data, offset, length, seg_start_offset, seg_end_offset, byte_va)
                
                print("Contents for new_asm : ", new_asm_content)

                if not new_asm_content:
                    print(f"[-] LLM failed to provide alternative for {rule_name}")
                    continue

                if isinstance(new_asm_content, list):
                    new_asm_str = "\n".join(new_asm_content)
                else:
                    new_asm_str = new_asm_content

                new_bytes = self.engine.assemble(new_asm_str)
                
                if not new_bytes:
                    print(f"[-] Failed to assemble replacement for: {rule_name}")
                    continue
                
                success, msg = patcher.apply_patch(offset, byte_va, new_bytes, length)
                
                if success:
                    print(f"[+] {msg}")
                    applied_any = True
                else:
                    print(f"[-] Patching failed for this offset: {msg}")

            if applied_any:
                patcher.save_variant(variant_path)
                current_file = variant_path
                self.project = angr.Project(current_file, auto_load_libs=False)
            else:
                print("[-] No patches could be applied in this iteration.")
                break
                
        print("\n[!] Loop finished. Final variant:", current_file)
        return current_file

    def validate(self, file_path):
        """Placeholder for functional validation."""
        return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python miser.py <target_binary>")
    else:
        target = sys.argv[1]
        if os.path.exists(target):
            miser = Miser(target, "rules")
            miser.run_evasion_loop()
        else:
            print(f"File not found: {target}")
