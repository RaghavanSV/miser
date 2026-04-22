import os
import angr
from struct import pack

class Patcher:
    def __init__(self, binary_path, project=None):
        self.binary_path = binary_path
        if project:
            self.project = project
        else:
            self.project = angr.Project(binary_path, auto_load_libs=False)
        
        with open(binary_path, "rb") as f:
            self.binary_data = bytearray(f.read())

    def find_code_cave(self, size_required):
        """Search for a sequence of 0x00 bytes in an executable section/segment."""
        main_obj = self.project.loader.main_object
        
        regions = main_obj.sections if hasattr(main_obj, 'sections') and main_obj.sections else main_obj.segments
        
        for region in regions:
            if region.is_executable:
                
                start_va = getattr(region, 'vaddr', getattr(region, 'min_addr', 0))
                size = getattr(region, 'memsize', getattr(region, 'vsize', 0))
                
                start_offset = main_obj.addr_to_offset(start_va)
                if start_offset is None:
                    continue
                
                region_data = self.binary_data[start_offset:start_offset + size]
                cave_index = region_data.find(b'\x00' * size_required)
                
                if cave_index != -1:
                    file_offset = start_offset + cave_index
                    va = start_va + cave_index
                    return file_offset, va
        
        return None, None

    def apply_patch(self, offset, va, new_bytes, original_length):
        """
        Applies patch. If new_bytes fits, use in-place.
        If not, use a code cave with JMP redirection.
        """
        if len(new_bytes) <= original_length:
            return self.apply_patch_inplace(offset, new_bytes, original_length)
        else:
            return self.apply_patch_cave(offset, va, new_bytes, original_length)

    def apply_patch_inplace(self, offset, new_bytes, original_length):
        """Option A: Patch at the original offset, NOP-pad if smaller."""
        padding_size = original_length - len(new_bytes)
        full_patch = new_bytes + (b'\x90' * padding_size)
        
        self.binary_data[offset : offset + original_length] = full_patch
        return True, "Patch applied successfully (In-place)."

    def apply_patch_cave(self, offset, va, new_bytes, original_length):
        """Option B: Write to code cave and jump back and forth."""
        if original_length < 5:
            return False, "Instruction too small for a JMP redirection (need 5 bytes)."
        
        cave_size = len(new_bytes) + 5
        cave_offset, cave_va = self.find_code_cave(cave_size)
        
        if not cave_offset:
            return False, "No suitable code cave found."
            
        return_va = va + original_length
        rel_back = return_va - (cave_va + len(new_bytes) + 5)
        
        jmp_back = b'\xE9' + pack('<i', rel_back)
        cave_payload = new_bytes + jmp_back
        
        self.binary_data[cave_offset : cave_offset + len(cave_payload)] = cave_payload
        
        rel_to_cave = cave_va - (va + 5)
        jmp_to_cave = b'\xE9' + pack('<i', rel_to_cave)
        
        padding = b'\x90' * (original_length - 5)
        
        self.binary_data[offset : offset + original_length] = jmp_to_cave + padding
        
        return True, f"Patch applied via Code Cave at VA {hex(cave_va)}."

    def save_variant(self, output_path):
        with open(output_path, "wb") as f:
            f.write(self.binary_data)
        return True

if __name__ == "__main__":
    pass
