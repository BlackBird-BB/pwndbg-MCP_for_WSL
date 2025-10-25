"""
AI Agent (Claude)
    ↕ JSON-RPC over stdio
MCP Server (Python)
    ↕ subprocess stdin/stdout
GDB Process + pwndbg
    ↕ text commands
Target Binary
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# MCP Server configuration
mcp = FastMCP("pwndbg-mcp-server", log_level="ERROR")

# Global GDB session variables
gdb_process = None
is_connected = False

# Whitelist of allowed pwndbg commands
ALLOWED_COMMANDS = {
    # Heap related
    "heap",
    "bins",
    "vis_heap_chunks",
    "heap chunks",
    "chunk",
    "fastbins",
    "smallbins",
    "largebins",
    "unsortedbin",
    "tcache",
    "arena",
    # Security related
    "checksec",
    "vmmap",
    "canary",
    "piebase",
    "procinfo",
    # Registers/Memory
    "registers",
    "regs",
    "stack",
    "telescope",
    "context",
    "hexdump",
    # Search/Analysis
    "search",
    "find",
    "got",
    "plt",
    "rop",
    "ropper",
    "strings",
    # Disassembly
    "disasm",
    "disassemble",
    "nearpc",
    "pdisass",
    # Execution control
    "break",
    "continue",
    "step",
    "next",
    "finish",
    "run",
    # Basic GDB commands
    "info",
    "print",
    "x",
    "examine",
    "backtrace",
    "bt",
    "frame",
    "set",
    "show",
    "list",
    "file",
    "load",
}


def _execute_safe_command(command: str) -> str:
    """Safe command execution"""
    global gdb_process, is_connected

    if not is_connected:
        return "Error: GDB session is not connected. Run start_debug_session() first."

    try:
        # Send command
        gdb_process.stdin.write(f"{command}\n")
        gdb_process.stdin.flush()

        import time
        import select

        output_lines = []
        start_time = time.time()
        timeout = 5.0
        buffer = ""

        while time.time() - start_time < timeout:
            ready, _, _ = select.select([gdb_process.stdout], [], [], 0.1)

            if ready:
                # Read byte by byte
                char = gdb_process.stdout.read(1)
                if char:
                    buffer += char

                    # Process completed line
                    if char == "\n":
                        line = buffer.rstrip("\n\r")
                        if line:  # Skip empty lines
                            output_lines.append(line)
                        buffer = ""

                        # Detect prompt (at end of line)
                        if line.endswith("pwndbg>"):
                            break

                    # Detect prompt (no newline case)
                    elif buffer.endswith("pwndbg>"):
                        if buffer.strip():
                            output_lines.append(buffer.rstrip())
                        break

                    # Output limit
                    if len(output_lines) > 200:
                        output_lines.append("... (output limit: 200 lines)")
                        break
                else:
                    # EOF or process termination
                    break
            else:
                # Continue waiting but check for output
                if output_lines and buffer == "":
                    time.sleep(0.05)  # Short wait before termination decision
                    ready, _, _ = select.select([gdb_process.stdout], [], [], 0.01)
                    if not ready:
                        break
                else:
                    time.sleep(0.1)

        # Process remaining buffer content
        if buffer.strip():
            output_lines.append(buffer.strip())

        # Return result
        if output_lines:
            result = "\n".join(output_lines)
            return result if result.strip() else f"Command '{command}' executed"
        else:
            return f"Command '{command}' executed (no response)"

    except Exception as e:
        return f"Command execution failed: {e}"


@mcp.tool()
def check_pwndbg_connection() -> str:
    """Check pwndbg connection status"""
    try:
        result = subprocess.run(["which", "gdb"], capture_output=True, text=True)
        if result.returncode != 0:
            return "Error: GDB is not installed"

        pwndbg_paths = [
            # Path.home() / ".gdbinit",
            # Path("/usr/share/pwndbg"),
            Path.home() / "pwndbg",
            "/usr/bin/pwndbg",
        ]

        pwndbg_found = any(path.exists() for path in pwndbg_paths)
        if not pwndbg_found:
            return "Warning: pwndbg may not be installed"

        if is_connected:
            return "✓ pwndbg MCP server connected (GDB session active)"
        else:
            return "✓ pwndbg available (GDB session inactive)"

    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def start_debug_session(binary_path: str = "") -> str:
    """Start GDB debugging session (binary path optional)"""
    global gdb_process, is_connected

    if is_connected:
        return "GDB session is already active. Run stop_debug_session() first."

    if binary_path and not os.path.exists(binary_path):
        return f"Error: Binary file not found: {binary_path}"

    try:
        gdb_cmd = ["pwndbg", "-q"]

        if binary_path:
            gdb_cmd.append(binary_path)
            success_msg = f"✓ GDB session started (binary: {binary_path})"
        else:
            success_msg = "✓ GDB session started (no binary)"

        gdb_cmd.extend(
            [
                "-ex",
                "set confirm off",
                "-ex",
                "set pagination off",
            ]
        )

        gdb_process = subprocess.Popen(
            gdb_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        is_connected = True
        return success_msg

    except Exception as e:
        gdb_process = None
        is_connected = False
        return f"GDB session start failed: {e}"


@mcp.tool()
def stop_debug_session() -> str:
    """Stop GDB debugging session"""
    global gdb_process, is_connected

    if not is_connected:
        return "GDB session is not active."

    try:
        if gdb_process:
            gdb_process.terminate()
        gdb_process = None
        is_connected = False
        return "✓ GDB session terminated."
    except Exception as e:
        return f"GDB session termination failed: {e}"


# ============================================================================
# Heap Analysis Tools
# ============================================================================


@mcp.tool()
def heap() -> str:
    """Complete heap status summary"""
    return _execute_safe_command("heap")


@mcp.tool()
def bins() -> str:
    """Check all bin status"""
    return _execute_safe_command("bins")


@mcp.tool()
def vis() -> str:
    """Visualize heap chunks"""
    return _execute_safe_command("vis_heap_chunks")


@mcp.tool()
def malloc_chunk(address: str) -> str:
    """Analyze specific chunk"""
    if not address:
        return "Error: Please enter an address"
    return _execute_safe_command(f"chunk {address}")


# ============================================================================
# Binary Security Tools
# ============================================================================


@mcp.tool()
def checksec() -> str:
    """Check binary security features"""
    return _execute_safe_command("checksec")


@mcp.tool()
def vmmap() -> str:
    """Memory mapping information"""
    return _execute_safe_command("vmmap")


@mcp.tool()
def canary() -> str:
    """Check stack canary"""
    return _execute_safe_command("canary")


# ============================================================================
# Registers/Memory Tools
# ============================================================================


@mcp.tool()
def regs() -> str:
    """Check register status"""
    return _execute_safe_command("registers")


@mcp.tool()
def stack() -> str:
    """Check stack contents"""
    return _execute_safe_command("stack")


@mcp.tool()
def telescope(address: str = "") -> str:
    """Memory dump (pointer tracing)"""
    if address:
        return _execute_safe_command(f"telescope {address}")
    return _execute_safe_command("telescope")


@mcp.tool()
def context() -> str:
    """Check entire context"""
    return _execute_safe_command("context")


# ============================================================================
# Search/Analysis Tools
# ============================================================================


@mcp.tool()
def search(pattern: str) -> str:
    """Search memory values"""
    if not pattern:
        return "Error: Please enter a pattern to search"
    return _execute_safe_command(f"search {pattern}")


@mcp.tool()
def find(pattern: str) -> str:
    """Find pattern"""
    if not pattern:
        return "Error: Please enter a pattern to search"
    return _execute_safe_command(f"find {pattern}")


@mcp.tool()
def got() -> str:
    """Check GOT table"""
    return _execute_safe_command("got")


@mcp.tool()
def plt() -> str:
    """Check PLT table"""
    return _execute_safe_command("plt")


@mcp.tool()
def rop() -> str:
    """Search ROP gadgets"""
    return _execute_safe_command("rop")


# ============================================================================
# Exception Handling Tool
# ============================================================================


@mcp.tool()
def execute_custom_command(command: str) -> str:
    """Execute user-defined commands for cases where AI cannot solve with basic tools (safety verified)"""
    if not command:
        return "Error: Please enter a command"

    # Command safety validation
    command_parts = command.split()
    if not command_parts:
        return "Error: Please enter a valid command"

    base_command = command_parts[0]

    # Whitelist validation
    if base_command not in ALLOWED_COMMANDS:
        return f"Error: Command not allowed. Available commands: {', '.join(sorted(ALLOWED_COMMANDS))}"

    # Dangerous command pattern check
    dangerous_patterns = [
        "rm",
        "del",
        "format",
        "mkfs",
        "dd if=",
        "dd of=",
        "sudo",
        "su",
        "chmod +x",
        "wget",
        "curl",
        "nc ",
        "netcat",
        "python -c",
        "perl -e",
        "ruby -e",
        "bash -c",
        "sh -c",
        "$(",
        "`",
        "&&",
        "||",
        ";",
        "|",
        ">",
        ">>",
        "<",
    ]

    for pattern in dangerous_patterns:
        if pattern in command.lower():
            return f"Error: Security risk pattern detected: {pattern}"

    # Command length limit (prevent overly long commands)
    if len(command) > 200:
        return "Error: Command too long (maximum 200 characters)"

    # Execute after safety validation passes
    try:
        result = _execute_safe_command(command)
        return f"✓ User-defined command executed: {command}\n\n{result}"
    except Exception as e:
        return f"User-defined command execution failed: {e}"


@mcp.tool()
def list_available_commands() -> str:
    """List all available pwndbg commands"""
    commands_by_category = {
        "Heap Analysis": [
            "heap",
            "bins",
            "vis_heap_chunks",
            "chunk",
            "fastbins",
            "smallbins",
            "largebin",
            "unsortedbin",
            "tcache",
            "arena",
        ],
        "Security Analysis": ["checksec", "vmmap", "canary", "piebase", "procinfo"],
        "Registers/Memory": [
            "registers",
            "regs",
            "stack",
            "telescope",
            "context",
            "hexdump",
        ],
        "Search/Analysis": ["search", "find", "got", "plt", "rop", "ropper", "strings"],
        "Disassembly": ["disasm", "disassemble", "nearpc", "pdisass"],
        "Execution Control": ["break", "continue", "step", "next", "finish", "run"],
        "Basic GDB": [
            "info",
            "print",
            "x",
            "examine",
            "backtrace",
            "bt",
            "frame",
            "set",
            "show",
            "list",
            "file",
            "load",
        ],
    }

    result = "=== Available pwndbg Commands ===\n\n"

    for category, commands in commands_by_category.items():
        result += f"📋 {category}:\n"
        for cmd in commands:
            result += f"  • {cmd}\n"
        result += "\n"

    result += "⚠️ Note: You can execute the above commands directly using execute_custom_command() tool.\n"
    result += "However, it is recommended to use dedicated tools for each function."

    return result


def main():
    parser = argparse.ArgumentParser(description="pwndbg MCP Server")
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol (stdio only)",
    )

    args = parser.parse_args()

    try:
        mcp.run()
    except KeyboardInterrupt:
        pass
    finally:
        global gdb_process, is_connected
        if gdb_process:
            gdb_process.terminate()
        gdb_process = None
        is_connected = False


if __name__ == "__main__":
    main()
