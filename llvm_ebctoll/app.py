import sys
from pathlib import Path

import fire
import lief


def main():
    fire.Fire(__main)


LLVM_BITCODE_SECTION = ".llvmbc"
LLVM_COMMAND_SECTION = ".llvmcmd"
LLVM_BITCODE_HEADER = bytes([0x42, 0x43, 0xc0, 0xde])
# Note(ergrelet): there's no real way to delimit the end of a module's flags
# so we assume that "-cc1" is always the first flag and thus use it as a
# delimiter
CLANG_COMMANDS_DELIMITER = "-cc1"


def __main(binary_path: str, output_directory: str) -> None:
    lief_bin = lief.parse(binary_path)
    if lief_bin is None:
        print(f"Failed to parse file '{binary_path}'")
        sys.exit(1)

    found_bc_modules = 0
    found_cmd_modules = 0
    output_directory_path = Path(output_directory)
    for section in lief_bin.sections:
        if section.name == LLVM_BITCODE_SECTION:
            found_bc_modules = __extract_bitcode_from_section(
                output_directory_path, section)
        elif section.name == LLVM_COMMAND_SECTION:
            found_cmd_modules = __extract_commands_from_section(
                output_directory_path, section)

    if found_bc_modules != found_cmd_modules:
        print("Mismatch between bitcode file count and command file count. "
              "Something must have gone wrong!")
        sys.exit(2)

    if found_bc_modules == 0:
        print(f"Bitcode not found in '{binary_path}'")
    else:
        print(f"Dumped bitcode and command files in {binary_path}")


def __extract_bitcode_from_section(output_directory: Path,
                                   section: lief.Section) -> int:
    """
    Split concatenated bitcode files and store each one in a separate file
    in `output_directory`.
    Return the number of module found.
    """
    section_bytes = section.content.tobytes()
    module_count = 0
    current_position = 0
    while current_position != -1:
        module_path = output_directory / f"module_{module_count}.bc"
        # Find the next BC header
        next_position = section_bytes.find(
            LLVM_BITCODE_HEADER, current_position + len(LLVM_BITCODE_HEADER))

        # Dump bitcode to a file
        if next_position == -1:
            # Last bitcode file, dump until end of section
            module_path.write_bytes(section_bytes[current_position:])
        else:
            # Dump until next header
            module_path.write_bytes(
                section_bytes[current_position:next_position])

        module_count += 1
        current_position = next_position

    return module_count


def __extract_commands_from_section(output_directory: Path,
                                    section: lief.Section) -> int:
    """
    Dump command-line flags passed to the clang frontend into seperate text
    files. There should be one such file for each bitcode module embedded in
    the binary.
    Return the number of module found.
    """
    section_bytes = section.content.tobytes()
    commands = list(
        map(lambda b: b.decode("ascii"), section_bytes.split(b'\x00')))

    module_count = 0
    current_position = 0
    while current_position != -1:
        commands_path = output_directory / f"clang_flags_{module_count}.txt"

        try:
            next_position = commands.index(CLANG_COMMANDS_DELIMITER,
                                           current_position + 1)
        except ValueError:
            next_position = -1

        # Dump commands to a file
        if next_position == -1:
            commands_path.write_text(" ".join(commands[current_position:]))
        else:
            commands_path.write_text(" ".join(
                commands[current_position:next_position]))

        module_count += 1
        current_position = next_position

    return module_count
