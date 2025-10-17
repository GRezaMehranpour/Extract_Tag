# SCL DB Analyzer

<!-- Add a screenshot of your application here! A good screenshot is the best way to show what your tool does. -->


A graphical desktop tool for parsing and analyzing Siemens SCL source files (`.scl`, `.db`, `.udt`). This application fully resolves complex Data Blocks (DBs) that use nested User-Defined Types (UDTs) and arrays, generating a flat list of all fully-qualified tag paths.

This is invaluable for generating documentation, creating tag import files for SCADA/HMI systems, or performing automated analysis on large PLC projects.

## The Problem It Solves

In Siemens TIA Portal or Step 7, a Data Block can be defined using complex UDTs, which can themselves contain other UDTs or arrays. Manually expanding a variable like `"MyMotor"[1]."Status"."ErrorCode"` across multiple files to find its full path is tedious and error-prone. This tool automates that entire process.

## Key Features

-   **UDT-Aware Parsing:** Scans an entire project folder to build a dictionary of all custom data types (`TYPE ... END_TYPE`).
-   **Recursive Tag Resolution:** Intelligently expands nested structs and UDTs to their primitive data types.
-   **Array Expansion:** Expands arrays with defined dimensions (e.g., `ARRAY[0..15] OF ...`) into individual tags (`Tag[0]`, `Tag[1]`, etc.).
-   **Batch Processing:** Analyze an entire folder of DB source files at once to generate a complete, unique tag list for the project.
-   **User-Friendly GUI:** Simple, three-panel interface to view the type dictionary, source code, and final resolved tags, with progress indicators for long operations.
-   **Powered by Tree-sitter:** Uses the robust `tree-sitter` parsing framework with a dedicated `tree-sitter-scl` grammar for accurate and fast parsing.

## Installation

This project uses modern Python packaging. A virtual environment is highly recommended.

**Prerequisites:**
*   Python 3.10 or newer.
*   Git must be installed and available in your system's PATH (required to install the `tree-sitter-scl` dependency directly from GitHub).

**Steps:**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/scl_db_analyzer.git
    cd scl_db_analyzer
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # On Windows
    python -m venv .venv
    .\.venv\Scripts\activate

    # On macOS/Linux
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install the project and its dependencies:**
    This command reads the `pyproject.toml` file and installs the application and the `run-analyzer` script into your virtual environment.
    ```bash
    pip install .
    ```

## How to Use

After installation, a command-line script is available to run the application.

1.  **Launch the application:**
    Open your terminal (with the virtual environment activated) and simply run:
    ```bash
    run-analyzer
    ```

2.  **Step 1: Scan for Types**
    -   Click the **"1. Scan Project Folder for Types..."** button.
    -   Select the root folder of your PLC project that contains **all** of your `.udt` and `.db` source files.
    -   The application will parse all files and populate the "Type Dictionary" panel on the left. The status label will turn green once complete. This step is crucial and must be done first.

3.  **Step 2: Analyze Files**
    You have two options:

    -   **Analyze a single file:** Click **"2. Analyze Single DB File..."** and select the specific `.db` file you want to inspect. The "Source Code" panel will show its contents, and the "Resolved Tag Paths" panel will show the results.

    -   **Analyze an entire folder (Batch Mode):** Click **"3. Analyze DB Folder..."** and select a folder containing one or more `.db` files. The application will process all of them and display a combined, sorted, and unique list of all tags found in the "Resolved Tag Paths" panel. A progress bar will show the status of the operation.

## How It Works

The tool operates in two main phases:

1.  **Indexing Phase:** When you scan the project folder, it recursively finds all `.udt` and `.db` files. It parses each one to find `TYPE ... END_TYPE` definitions and stores their structure (field names and data types) in an internal dictionary.

2.  **Resolution Phase:** When you analyze a DB file, it parses the variable declarations. For each variable:
    -   If the data type is a primitive (like `BOOL` or `INT`), it records the full tag path.
    -   If the data type is a UDT, it looks up that UDT in the dictionary created in Phase 1 and recursively resolves each field inside it, prepending the parent variable's name.
    -   This process continues until all branches of the data structure have been explored.

## Dependencies

-   **GUI:** `tkinter` (part of the Python standard library)
-   **Parsing Engine:** [tree-sitter](https://github.com/tree-sitter/py-tree-sitter)
-   **SCL Grammar:** [tree-sitter-scl](https://github.com/tastenmo/tree-sitter-scl)

## Contributing / Developer Setup

If you wish to contribute to the development of this tool, fix bugs, or add features, you should perform an **editable install**. This allows you to make changes to the source code and have them take effect immediately without reinstalling.

Follow the installation steps above, but in Step 3, use this command instead:

```bash
# Use this command for a developer setup
pip install -e .
