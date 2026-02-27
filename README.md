## ⚙️ winproc: Windows Process Management and Thread Utility

**winproc** is a simple command-line application that lets you manage Windows processes, query thread information, and manipulate execution states (suspend/resume/kill) directly from your terminal.

### Application Usage: 💻 ➝ ⚙️ <small>`CLI → Process`</small>

Explore the functionality of `winproc` through these common operations:

#### 📋 List Processes
> Retrieve a comprehensive list of all currently running processes.
```bash
winproc -list
```
> **JSON Output**: Append `--json` to format the output for automated parsing.
```bash
winproc -list --json
```

#### 💀 Terminate a Process
> Forcefully terminate a process using either its executable name or Process ID (PID).
```bash
winproc -kill notepad.exe
```

#### ⏸️ Suspend / ▶️ Resume
> Pause or resume the execution of an entire process by its PID.
```bash
winproc -suspend 1234
winproc -resume 1234
```

#### 🔍 Query Information
> Gather detailed information about a specific process, including thread start addresses.
```bash
winproc -query explorer.exe
winproc -query 1234 -thread .*
```

#### 🧵 Thread-Level Control
> Target individual threads within a process to suspend, resume, or query them independently.
```bash
winproc -suspend 1234 -thread 5678
```

---

## ✅ Prerequisites

Before building this project, ensure the following are installed:

1. **[Visual Studio Community 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=17)** *or* **[Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)**
2. **Desktop Development with C++** workload (Install via the Visual Studio Installer).
3. **Windows 11 SDK** (version 10.0.22621.0 or later). Install via the Visual Studio Installer if not already available.
4. **CMake 3.26** or later.

---

## 🧱 Building the Project

Follow these steps to build the project using VS Code:

1. **Open the Project in VS Code.**
2. **Install the [CMake Tools extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cmake-tools).**
3. **Configure & Build:**
   - Open the command palette (`Ctrl+Shift+P`) and run **CMake: Configure**.
   - After configuration completes, run **CMake: Build**.

*Note: The project requires `dbghelp.dll` and `symsrv.dll`, which are automatically copied post-build from the Visual Studio Diagnostics Hub for accurate thread start address resolution.*

---

## ❗ Troubleshooting

* **Missing Dependencies:**
  Double-check that the required Visual Studio workload and Windows SDK are installed.

* **Build Errors / Missing Symbols:**
  Ensure that you have installed the "Desktop Development with C++" workload and that your Windows SDK is up to date. The build script attempts to copy diagnostic DLLs (`dbghelp.dll`, `symsrv.dll`) from the Visual Studio Diagnostics Hub.

* **CMake Not Detected in VS Code:**
  Try reloading the window or verifying your VS Code extension and kit configuration.
