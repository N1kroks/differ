import argparse
import lief
from rich.console import Console
from rich.table import Table
from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_ARM
from typing import List, Dict, Tuple

HEX_DIFF_SIZE = 16
PE_MODES = {
    lief.PE.Header.MACHINE_TYPES.ARM64: (CS_ARCH_ARM64, CS_MODE_ARM),
    lief.PE.Header.MACHINE_TYPES.ARMNT: (CS_ARCH_ARM, CS_MODE_ARM),
    lief.PE.Header.MACHINE_TYPES.ARM: (CS_ARCH_ARM, CS_MODE_ARM),
}
ELF_MODES = {
    lief.ELF.ARCH.AARCH64: (CS_ARCH_ARM64, CS_MODE_ARM),
    lief.ELF.ARCH.ARM: (CS_ARCH_ARM, CS_MODE_ARM),
}

console = Console(highlight=False)
skip_ranges: List[Tuple[int, int]] = []


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("file1", help="The first file to compare")
    parser.add_argument("file2", help="The second file to compare")
    parser.add_argument(
        "--diff-signature",
        action="store_true",
        help="Diff the signature section of the PE file",
    )
    return parser.parse_args()


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def format_hex_line(chunk: bytes, compare_chunk: bytes) -> str:
    hex_parts: List[str] = []
    ascii_parts: List[str] = []
    for i in range(HEX_DIFF_SIZE):
        if i < len(chunk):
            byte = chunk[i]
            char = chr(byte) if 32 <= byte < 127 else "."
            if i < len(compare_chunk) and byte != compare_chunk[i]:
                hex_parts.append(f"[blue]{byte:02x}[/blue]")
                ascii_parts.append(f"[blue]{char}[/blue]")
            else:
                hex_parts.append(f"{byte:02x}")
                ascii_parts.append(char)
        else:
            hex_parts.append("00")
            ascii_parts.append(".")
        if (i + 1) % 8 == 0:
            hex_parts.append("")

    hex_str = " ".join(hex_parts)
    ascii_str = "".join(ascii_parts)

    return f"\t{hex_str}\t|{ascii_str}|"


def get_fields(binary: lief.Binary) -> Dict[str, str]:
    if binary.format == lief.Binary.FORMATS.PE:
        return {
            "Machine": f"{binary.header.machine}",
            "TimeDateStamp": f"0x{binary.header.time_date_stamps:08X}",
            "Entrypoint": f"0x{binary.optional_header.addressof_entrypoint:16X}",
            "ImageBase": f"0x{binary.optional_header.imagebase:016X}",
            "SizeOfImage": f"0x{binary.optional_header.sizeof_image:08X}",
            "CheckSum": f"0x{binary.optional_header.checksum:08X}",
        }
    elif binary.format == lief.Binary.FORMATS.ELF:
        return {
            "Machine": f"{binary.header.machine_type}",
            "Entrypoint": f"0x{binary.header.entrypoint:016X}",
        }
    return {}


def get_executable_sections(binary: lief.Binary) -> lief.Section:
    sections = []
    if isinstance(binary, lief.PE.Binary):
        sections.extend(
            s
            for s in binary.sections
            if s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
        )
    elif isinstance(binary, lief.ELF.Binary):
        sections.extend(
            s
            for s in binary.sections
            if s.has(lief.ELF.Section.FLAGS.EXECINSTR)
        )
        if not sections:
            sections.extend(
                seg for seg in binary.segments if lief.ELF.Segment.FLAGS.X in seg.flags
            )
    return sections


def dissasmble_diff(
    bin1: lief.Binary,
    bin2: lief.Binary,
    data1: bytes,
    data2: bytes,
    diff_offsets: List[int],
) -> None:
    mode_map = PE_MODES if bin1.format == lief.Binary.FORMATS.PE else ELF_MODES
    mode1 = mode_map.get(
        bin1.header.machine
        if bin1.format == lief.Binary.FORMATS.PE
        else bin1.header.machine_type,
        (None, None),
    )
    mode2 = mode_map.get(
        bin2.header.machine
        if bin2.format == lief.Binary.FORMATS.PE
        else bin2.header.machine_type,
        (None, None),
    )

    if None in mode1 or None in mode2:
        arch1 = bin1.header.machine if bin1.format == lief.Binary.FORMATS.PE else bin1.header.machine_type
        arch2 = bin2.header.machine if bin2.format == lief.Binary.FORMATS.PE else bin2.header.machine_type
        console.print(f"[bold red]Cannot compare disassembly unknown arch: {arch1}, {arch2}[/bold red]")
        return

    if mode1 != mode2:
        console.print("[bold red]Cannot compare disassembly with different arch[/bold red]")
        return

    md = Cs(mode1[0], mode1[1])
    sections = get_executable_sections(bin1)

    for addr in diff_offsets:
        for section in sections:
            offset = (
                section.offset
                if isinstance(section, lief.PE.Section)
                else section.file_offset
            )
            size = (
                section.sizeof_raw_data
                if isinstance(section, lief.PE.Section)
                else section.physical_size
            )
            if offset <= addr < offset + size:
                rva = section.virtual_address + (addr - offset)
                break
        else:
            continue

        code1 = data1[addr : addr + HEX_DIFF_SIZE]
        code2 = data2[addr : addr + HEX_DIFF_SIZE]

        addr1 = bin1.imagebase + rva if bin1.format == lief.Binary.FORMATS.PE else rva
        addr2 = bin2.imagebase + rva if bin2.format == lief.Binary.FORMATS.PE else rva
        instr1 = list(md.disasm(code1, addr1))
        instr2 = list(md.disasm(code2, addr2))

        for i in range(max(len(instr1), len(instr2))):
            line1 = f"{instr1[i].mnemonic}\t{instr1[i].op_str}".replace("[", r"\[")
            line2 = f"{instr2[i].mnemonic}\t{instr2[i].op_str}".replace("[", r"\[")
            if line1 != line2:
                console.print(
                    f"[red]<{instr1[i].address:08x}[/red]\t[blue]{line1}[/blue]"
                )
                console.print("---")
                console.print(
                    f"[green]>{instr2[i].address:08x}[/green]\t[blue]{line2}[/blue]"
                )


def main(file1: str, file2: str, diff_signature: bool):
    lief_file = True

    data1, data2 = read_file(file1), read_file(file2)
    bin1, bin2 = lief.parse(file1), lief.parse(file2)

    if bin1 is None or bin2 is None:
        console.print(
            f"[red]Error parsing files: {file1} or {file2}\nOnly Hex Diff will be provided[/red]"
        )
        lief_file = False

    if lief_file:
        if bin1.format != bin2.format:
            console.print("[red]Cannot compare files: different formats[/red]")
            return

    console.print(f"[bold]Comparing {file1} and {file2}...[/bold]")

    if lief_file:
        if bin1.format == lief.Binary.FORMATS.PE and not diff_signature:
            section1 = bin1.data_directories[
                lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE
            ]
            section2 = bin1.data_directories[
                lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE
            ]
            skip_ranges.append(
                (section1.rva, section1.rva + max(section1.size, section2.size))
            )

    if lief_file:
        table = Table()
        table.add_column("Field")
        table.add_column("File 1")
        table.add_column("File 2")

        fields1 = get_fields(bin1)
        fields2 = get_fields(bin2)

        diff_found = False
        for field in fields1:
            val1 = fields1[field]
            val2 = fields2[field]
            if val1 != val2:
                table.add_row(field, val1, val2)
                diff_found = True

        if diff_found:
            console.print("[bold]ELF/PE Header diff:[/bold]")
            console.print(table)

    max_len = max(len(data1), len(data2))
    diff_offsets = []

    console.print("[bold]Hex diff:[/bold]")
    for addr in range(0, max_len, HEX_DIFF_SIZE):
        if any(start <= addr < end for start, end in skip_ranges):
            continue

        chunk1 = data1[addr : addr + HEX_DIFF_SIZE]
        chunk2 = data2[addr : addr + HEX_DIFF_SIZE]

        if chunk1 != chunk2:
            diff_offsets.append(addr)
            console.print(f"[red]<{addr:08x}[/red]{format_hex_line(chunk1, chunk2)}")
            console.print("---")
            console.print(
                f"[green]<{addr:08x}[/green]{format_hex_line(chunk2, chunk1)}"
            )

    if lief_file:
        console.print("[bold]Disassembly diff:[/bold]")
        dissasmble_diff(bin1, bin2, data1, data2, diff_offsets)

def start():
    main(**vars(parse_args()))

if __name__ == "__main__":
    start()
