from capstone import *
from keystone import *
import json
import re
from langchain_core.messages import HumanMessage, SystemMessage


class BaseLLM:
    def generate(self, system_prompt, user_prompt):
        print(f"DEBUG Prompt: {user_prompt[:100]}...")
        return "PLACEHOLDER: LLM Response needed"

class RefactorEngine:
    def __init__(self, arch="x64", llm=None):
        self.arch_name = arch
        if arch == "x64":
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        elif arch == "x86":
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        else:
            raise ValueError("Unsupported architecture")
        
        self.llm = llm

    def disassemble_context(self, binary_data, offset, length, seg_start_offset, seg_end_offset, byte_va, context_size=64):
        """
        Disassembles bytes around the target offset to provide context.
        Uses file offsets for slicing and VAs for disassembly mapping.
        """
        start = max(seg_start_offset, offset - context_size)
        end = min(seg_end_offset, offset + length + context_size)

        print(f"offset={offset}, length={length}, byte_va={hex(byte_va)}")
        print(f"LOG: Chunk start offset: {start} and Chunk end offset: {end}")
        
        target_range = range(byte_va, byte_va + length)
        chunk = binary_data[start:end]
        
        base_va = byte_va - (offset - start)
        
        instructions = []
        for insn in self.cs.disasm(chunk, base_va):
            ins_address = insn.address
            is_target = ins_address in target_range
            
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
                "bytes": insn.bytes.hex(),
                "is_target": is_target
            })
        return instructions

    def is_valid_block(self, binary_data, offset, length):
        """Disassembles the given bytes and verifies they are valid instructions."""
        chunk = binary_data[offset:offset+length]
        if not chunk:
            return False
            
        total_size = 0
        try:
            for insn in self.cs.disasm(chunk, offset):
                if not re.match(r"^[a-z0-9]{2,10}$", insn.mnemonic):
                    print(f"LOG: Mnemonic '{insn.mnemonic}' failed regex validation.")
                    return False
                total_size += insn.size
        except Exception as e:
            print(f"LOG: Disassembly error during validation: {e}")
            return False
            
        if total_size != length:
            print(f"LOG: Disassembled {total_size} bytes, but hit length was {length}.")
            return False
            
        return True

    def format_for_llm(self, instructions, target_only=True):
        """Formats the instruction list into a clear prompt."""
        output = ""
        for insn in instructions:
            if target_only and not insn["is_target"]:
                continue
            print(f"LOG priting each instruction from the context range -> {insn}")
            tag = "[DETECTED]" if insn["is_target"] else ""
            output += f"{insn['address']}: {insn['mnemonic']} {insn['op_str']} {tag}\n"
        return output

    def assemble(self, asm_code):
        """Assembles a string of assembly into bytes."""
        try:
            encoding, _ = self.ks.asm(asm_code)
            return bytes(encoding)
        except KsError as e:
            print(f"Assembly Error: {e}")
            return None

    def refactor(self, binary_data, offset, length, seg_start_offset, seg_end_offset, byte_va):
        """The core loop: Disassemble -> LLM (Gen) -> LLM (Verify) -> Assemble."""
        insns = self.disassemble_context(binary_data, offset, length, seg_start_offset, seg_end_offset, byte_va)
        if not insns:
            return None, None
        asm_context = self.format_for_llm(insns, target_only=True)

        print(f"LOG: asm_context -> {asm_context}")
        
        system_gen = "You are an expert assembly programmer. Replace the instructions marked [DETECTED] with equivalent logic of same or smaller size."
        user_gen = f"Context:\n{asm_context}\n\nProvide only the new assembly for the [DETECTED] block."
        
        new_asm = self.llm.invoke([
                    SystemMessage(content=system_gen),
                    HumanMessage(content=user_gen)
                ])
                        
        system_verify = "You are a logic auditor. Check if the provided alternative assembly is logically identical to the original and doesn't break context."
        user_verify = f"Original:\n{asm_context}\n\nSuggested Replacement:\n{new_asm.content}\n\nIs it identical in function? Answer YES/NO with reasoning."
        
        verification = self.llm.invoke([
            SystemMessage(content=system_verify), 
            HumanMessage(content=user_verify)
            ])
        
        print(f"LOG: verification -> {verification}")


        return new_asm.content, verification.content

if __name__ == "__main__":
    test_bytes = bytes.fromhex("4831c048ffc0")
    engine = RefactorEngine("x64")
    
    insns = engine.disassemble_context(test_bytes, 3, 3)
    print("Disassembled Context:")
    print(engine.format_for_llm(insns))
