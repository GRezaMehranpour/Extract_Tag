# gui_udt_resolver_v9.py (Final Merging Logic)
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from pathlib import Path
import sys
import threading
from queue import Queue, Empty
import time  # <-- ADDED for timing analysis

try:
    from tree_sitter import Parser, Node
    from tree_sitter_scl import language
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Dependency Error",
        "Required libraries not found.\n\n"
        "Please ensure your virtual environment is active and all dependencies are installed."
    )
    sys.exit(1)

def get_node_text(node: Node) -> str:
    """Safely gets the text of a node, stripping quotes and leading/trailing whitespace."""
    if not node:
        return ""
    return node.text.decode('utf8').strip().strip('"')

class SclUdtResolverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SCL UDT-Aware Tag Finder (v9 - Final Merging Logic)")
        self.root.geometry("1600x900")
        self.parser = Parser()
        self.parser.language = language
        self.udt_dictionary = {}
        self.queue = Queue()
        self._create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.processing_thread = None
        self._process_queue()

    # --- UI and Helper functions are correct and unchanged ---
    def _create_widgets(self):
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X, side=tk.TOP)
        self.scan_button = ttk.Button(top_frame, text="1. Scan Project Folder for Types...", command=self.scan_project_folder)
        self.scan_button.pack(side=tk.LEFT)
        self.analyze_file_button = ttk.Button(top_frame, text="2. Analyze Single DB File...", command=self.analyze_source_file)
        self.analyze_file_button.pack(side=tk.LEFT, padx=10)
        self.analyze_folder_button = ttk.Button(top_frame, text="3. Analyze DB Folder...", command=self.analyze_db_folder)
        self.analyze_folder_button.pack(side=tk.LEFT)
        self.udt_status_label = ttk.Label(top_frame, text="Types not scanned.", foreground="red")
        self.udt_status_label.pack(side=tk.LEFT, padx=10)
        main_pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        udt_frame = ttk.Frame(main_pane, padding=5)
        ttk.Label(udt_frame, text="Type Dictionary", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.udt_text = scrolledtext.ScrolledText(udt_frame, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED)
        self.udt_text.pack(fill=tk.BOTH, expand=True)
        main_pane.add(udt_frame, weight=1)
        source_frame = ttk.Frame(main_pane, padding=5)
        ttk.Label(source_frame, text="Source Code (Last Processed File)", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.source_text = scrolledtext.ScrolledText(source_frame, wrap=tk.WORD, font=("Consolas", 11), state=tk.DISABLED)
        self.source_text.pack(fill=tk.BOTH, expand=True)
        main_pane.add(source_frame, weight=2)
        results_notebook = ttk.Notebook(main_pane)
        main_pane.add(results_notebook, weight=2)
        tags_frame = ttk.Frame(results_notebook, padding=5)
        ttk.Label(tags_frame, text="Resolved Tag Paths", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.tags_text = scrolledtext.ScrolledText(tags_frame, wrap=tk.WORD, font=("Consolas", 11), state=tk.DISABLED)
        self.tags_text.pack(fill=tk.BOTH, expand=True)
        results_notebook.add(tags_frame, text="Results")
        log_frame = ttk.Frame(results_notebook, padding=5)
        log_top_frame = ttk.Frame(log_frame)
        log_top_frame.pack(fill=tk.X, anchor=tk.W)
        ttk.Label(log_top_frame, text="Logs & Errors", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        ttk.Button(log_top_frame, text="Clear Log", command=lambda: self._clear_text_widget(self.log_text)).pack(side=tk.RIGHT)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED, background="#f0f0f0")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        results_notebook.add(log_frame, text="Logs")
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 5))
        self.progress_bar = ttk.Progressbar(bottom_frame, orient='horizontal', mode='determinate')
        self.progress_bar.pack(fill=tk.X)
        self.status_var = tk.StringVar(value="Ready. Please scan a project folder first.")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5).pack(fill=tk.X, side=tk.BOTTOM)
    def _start_processing(self):
        self.root.config(cursor="watch")
        self.scan_button.config(state=tk.DISABLED)
        self.analyze_file_button.config(state=tk.DISABLED)
        self.analyze_folder_button.config(state=tk.DISABLED)
    def _end_processing(self):
        self.root.config(cursor="")
        self.scan_button.config(state=tk.NORMAL)
        self.analyze_file_button.config(state=tk.NORMAL)
        self.analyze_folder_button.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        self.processing_thread = None
    def _process_queue(self):
        try:
            while not self.queue.empty():
                msg_type, data = self.queue.get_nowait()
                if msg_type == "status": self.status_var.set(data)
                elif msg_type == "progress":
                    self.progress_bar['maximum'] = data[1]
                    self.progress_bar['value'] = data[0]
                elif msg_type == "log_error": self._append_to_text_widget(self.log_text, f"ERROR: {data}\n", "red")
                elif msg_type == "log_info": self._append_to_text_widget(self.log_text, f"INFO: {data}\n")
                elif msg_type == "udt_dictionary":
                    self.udt_dictionary = data
                    self._display_udt_dictionary()
                    self.udt_status_label.config(text=f"Loaded {len(self.udt_dictionary)} UDTs.", foreground="green")
                elif msg_type == "results": self._display_results(data)
                elif msg_type == "source": self._display_source(data)
                elif msg_type == "done":
                    self.status_var.set(data)
                    self._end_processing()
        finally:
            self.root.after(100, self._process_queue)
    # --- END UI and Helper functions ---

    def scan_project_folder(self):
        folder_path = filedialog.askdirectory(title="Select folder containing ALL source files (UDTs and DBs)")
        if not folder_path: return
        self._start_processing()
        self._clear_text_widget(self.tags_text)
        # Scan should start with a completely empty dictionary
        self.processing_thread = threading.Thread(target=self._worker_scan_project, args=(folder_path, True), daemon=True)
        self.processing_thread.start()

    def _worker_scan_project(self, folder_path, is_master_scan):
        # Master scan starts fresh, subsequent scans can build on existing dicts
        local_udt_dict = {} if is_master_scan else self.udt_dictionary.copy()
        try:
            self.queue.put(("status", f"Scanning {folder_path} for all type definitions..."))
            source_files = list(Path(folder_path).rglob("*.udt")) + list(Path(folder_path).rglob("*.db"))
            if not source_files:
                if is_master_scan:
                    messagebox.showinfo("No Files Found", "No '.udt' or '.db' files were found in the selected folder.")
                    self.queue.put(("done", "Scan complete. No source files found."))
                return

            total_files = len(source_files)
            for i, file in enumerate(source_files):
                if is_master_scan:
                    self.queue.put(("status", f"Scanning {i+1}/{total_files}: {file.name}..."))
                    self.queue.put(("progress", (i + 1, total_files)))
                self._parse_and_add_udts_from_file(file, local_udt_dict)
            
            if is_master_scan:
                self.queue.put(("udt_dictionary", local_udt_dict))
                self.queue.put(("done", "Type scan complete. Ready to analyze a source file."))
            else:
                # If not master scan, it's a pre-scan, so just return the result
                return local_udt_dict

        except Exception as e:
            self.queue.put(("log_error", f"Unhandled exception during project scan: {e}"))
            if is_master_scan:
                self.queue.put(("done", "Type scan failed."))
        return local_udt_dict

    def _parse_and_add_udts_from_file(self, filepath: Path, udt_dict):
        try:
            tree = self.parser.parse(filepath.read_bytes())
            for type_def_node in tree.root_node.children:
                if type_def_node.type == 'type_definition':
                    udt_name_node = type_def_node.child_by_field_name('name')
                    if not udt_name_node: continue
                    udt_name = get_node_text(udt_name_node)
                    
                    if udt_name not in udt_dict:
                        udt_dict[udt_name] = []
                    
                    for child in type_def_node.children:
                        if child.type == 'struct_definition':
                            for field_node in child.children:
                                if field_node.type == 'fields':
                                    field_name = get_node_text(field_node.child_by_field_name('name'))
                                    field_type_node = next((c for c in field_node.children if c.type == 'type'), None)
                                    udt_dict[udt_name].append((field_name, field_type_node))
        except Exception as e:
            self.queue.put(("log_error", f"Error parsing UDTs from {filepath.name}: {e}"))
            
    def analyze_source_file(self, filepath_str=None):
        if not self.udt_dictionary:
            messagebox.showwarning("Warning", "Please scan a project folder first.")
            return
        if not filepath_str:
            filepath_str = filedialog.askopenfilename(title="Select a DB file", filetypes=[("DB Files", "*.db"), ("All Files", "*.*")])
        if not filepath_str: return
        self._start_processing()
        self.processing_thread = threading.Thread(target=self._worker_analyze_file, args=(filepath_str,), daemon=True)
        self.processing_thread.start()

    # --- MODIFIED with Timer ---
    def _worker_analyze_file(self, filepath_str):
        start_time = time.perf_counter() # Start the timer
        try:
            filepath = Path(filepath_str)
            self.queue.put(("status", f"Analyzing {filepath.name}..."))
            
            # Start with the master dictionary and merge in types from this specific file.
            analysis_dict = self.udt_dictionary.copy()
            self._parse_and_add_udts_from_file(filepath, analysis_dict)
            
            source_bytes = filepath.read_bytes()
            self.queue.put(("source", source_bytes.decode('utf-8', errors='replace')))
            tree = self.parser.parse(source_bytes)
            
            if tree.root_node.has_error:
                self.queue.put(("log_info", f"File '{filepath.name}' contains syntax errors. Results may be incomplete."))
            
            # Analyze using the merged, contextual dictionary.
            all_tags = self._analyze_file_contents(tree.root_node, analysis_dict)
            
            # Calculate duration and update the log message
            duration = time.perf_counter() - start_time
            self.queue.put(("log_info", f"Extracted {len(all_tags)} tags from {filepath.name} in {duration:.3f} seconds."))

            self.queue.put(("results", sorted(list(all_tags))))
            self.queue.put(("status", f"Analysis of {filepath.name} complete. Found {len(all_tags)} resolved tag paths."))
        except Exception as e:
            self.queue.put(("log_error", f"Failed to analyze file {filepath_str}: {e}"))
        finally:
            self.queue.put(("done", "Analysis complete."))
            
    def analyze_db_folder(self):
        if not self.udt_dictionary:
            messagebox.showwarning("Warning", "Please scan a project folder first.")
            return
        folder_path_str = filedialog.askdirectory(title="Select folder containing DB files to analyze")
        if not folder_path_str: return
        self._start_processing()
        self._clear_text_widget(self.tags_text)
        self._clear_text_widget(self.source_text)
        self.processing_thread = threading.Thread(target=self._worker_analyze_folder, args=(folder_path_str,), daemon=True)
        self.processing_thread.start()

    # --- MODIFIED with Timers ---
    def _worker_analyze_folder(self, folder_path_str):
        total_start_time = time.perf_counter() # Timer for the whole operation
        all_tags_from_folder = set() # Initialize here to be available in finally block
        try:
            folder_path = Path(folder_path_str)
            self.queue.put(("status", f"Finding .db files in {folder_path}..."))
            db_files = list(folder_path.rglob("*.db"))
            if not db_files:
                messagebox.showinfo("No Files Found", "No '.db' files were found in the selected folder.")
                self.queue.put(("done", "Batch scan complete. No .db files found."))
                return

            # --- PASS 1: Build the complete contextual dictionary ---
            self.queue.put(("status", "Pre-scanning folder for contextual types..."))
            analysis_dict = self.udt_dictionary.copy()
            for filepath in db_files:
                self._parse_and_add_udts_from_file(filepath, analysis_dict)

            # --- PASS 2: Analyze tags using the complete dictionary ---
            total_files = len(db_files)
            for i, filepath in enumerate(db_files):
                file_start_time = time.perf_counter() # Timer for each individual file
                self.queue.put(("status", f"Analyzing {i+1}/{total_files}: {filepath.name}..."))
                self.queue.put(("progress", (i + 1, total_files)))
                try:
                    tree = self.parser.parse(filepath.read_bytes())
                    tags_from_file = self._analyze_file_contents(tree.root_node, analysis_dict)
                    
                    # Log duration for individual file
                    duration = time.perf_counter() - file_start_time
                    self.queue.put(("log_info", f"Extracted {len(tags_from_file)} tags from {filepath.name} in {duration:.3f} seconds."))
                    
                    all_tags_from_folder.update(tags_from_file)
                except Exception as e:
                    self.queue.put(("log_error", f"Failed to process {filepath.name}: {e}"))

            self.queue.put(("results", sorted(list(all_tags_from_folder))))
        except Exception as e:
             self.queue.put(("log_error", f"Unhandled exception during folder analysis: {e}"))
        finally:
            # Log total duration for the entire batch operation
            total_duration = time.perf_counter() - total_start_time
            self.queue.put(("done", f"Batch analysis complete. Found {len(all_tags_from_folder)} total unique tags in {total_duration:.2f} seconds."))

    # --- The core resolving logic below is correct and unchanged ---
    def _analyze_file_contents(self, root_node, udt_dict):
        all_found_tags = set()
        for node in root_node.children:
            if node.type == 'data_block':
                tags_from_db = self._resolve_db_tags(node, udt_dict)
                all_found_tags.update(tags_from_db)
        return all_found_tags
    def _resolve_db_tags(self, db_node, udt_dict):
        db_name_node = db_node.child_by_field_name('name')
        if not db_name_node: return set()
        db_name = get_node_text(db_name_node)
        resolved_tags, base_tags_to_process = set(), []
        implicit_type_node = db_node.child_by_field_name('type')
        if implicit_type_node:
            base_tags_to_process.append(("", implicit_type_node))
        else:
            for var_section in db_node.children_by_field_name('variable_declaration_section'):
                for var_decl in var_section.children_by_field_name('variable_declaration'):
                    tag_name = get_node_text(var_decl.child_by_field_name('name'))
                    tag_type_node = var_decl.child_by_field_name('data_type')
                    if tag_name and tag_type_node:
                        base_tags_to_process.append((tag_name, tag_type_node))
            struct_nodes = [child for child in db_node.children if child.type == 'struct_definition']
            for struct_def in struct_nodes:
                 for field_node in struct_def.children:
                    if field_node.type == 'fields':
                        field_name = get_node_text(field_node.child_by_field_name('name'))
                        field_type_node = next((c for c in field_node.children if c.type == 'type'), None)
                        base_tags_to_process.append((field_name, field_type_node))
        for tag_name, tag_type_node in base_tags_to_process:
            base_path = db_name if tag_name == "" else f"{db_name}.{tag_name}"
            self._expand_tag(base_path, tag_type_node, resolved_tags, udt_dict)
        return resolved_tags
    def _expand_tag(self, base_path, type_node, resolved_tags, udt_dict):
        if not type_node: return
        struct_def_node = next((c for c in type_node.children if c.type == 'struct_definition'), None)
        if struct_def_node:
            for field_node in struct_def_node.children:
                if field_node.type == 'fields':
                    sub_tag_name = get_node_text(field_node.child_by_field_name('name'))
                    sub_type_node = next((c for c in field_node.children if c.type == 'type'), None)
                    new_base_path = f"{base_path}.{sub_tag_name}"
                    self._expand_tag(new_base_path, sub_type_node, resolved_tags, udt_dict)
            return
        array_def_node = next((c for c in type_node.children if c.type == 'array_type'), None)
        if array_def_node:
            base_type_node_of_array = array_def_node.children[-1]
            dim_nodes = [c for c in array_def_node.children if c.type == 'integer_literal']
            if len(dim_nodes) > 0 and len(dim_nodes) % 2 == 0:
                dimensions = []
                try:
                    for i in range(0, len(dim_nodes), 2):
                        start = int(get_node_text(dim_nodes[i]))
                        end = int(get_node_text(dim_nodes[i+1]))
                        dimensions.append((start, end))
                    self._expand_array_dimensions(base_path, dimensions, base_type_node_of_array, resolved_tags, udt_dict)
                    return
                except (ValueError, IndexError) as e:
                    self.queue.put(("log_error", f"Could not parse array dimensions for '{base_path}': {e}"))
            self._expand_tag(f"{base_path}[]", base_type_node_of_array, resolved_tags, udt_dict)
            return
        clean_type_name = get_node_text(type_node)
        if clean_type_name in udt_dict:
            for sub_tag_name, sub_tag_type_node in udt_dict[clean_type_name]:
                new_base_path = f"{base_path}.{sub_tag_name}"
                self._expand_tag(new_base_path, sub_tag_type_node, resolved_tags, udt_dict)
        else:
            resolved_tags.add(base_path)
    def _expand_array_dimensions(self, current_path, remaining_dims, base_type_node, resolved_tags, udt_dict):
        if not remaining_dims:
            self._expand_tag(current_path, base_type_node, resolved_tags, udt_dict)
            return
        current_dim_start, current_dim_end = remaining_dims[0]
        next_dims = remaining_dims[1:]
        for i in range(current_dim_start, current_dim_end + 1):
            new_path = f"{current_path}[{i}]"
            self._expand_array_dimensions(new_path, next_dims, base_type_node, resolved_tags, udt_dict)
    def _display_udt_dictionary(self):
        self.udt_text.config(state=tk.NORMAL)
        self.udt_text.delete('1.0', tk.END)
        text_to_insert = ""
        for udt_name, fields in sorted(self.udt_dictionary.items()):
            text_to_insert += f"TYPE {udt_name}:\n"
            field_names = set()
            unique_fields = []
            for field in fields:
                if field[0] not in field_names:
                    field_names.add(field[0])
                    unique_fields.append(field)
            for field_name, field_type_node in unique_fields:
                field_type_text = get_node_text(field_type_node) if field_type_node else "UNKNOWN"
                text_to_insert += f"  - {field_name}: {field_type_text}\n"
            text_to_insert += "\n"
        self.udt_text.insert('1.0', text_to_insert if text_to_insert else "No UDTs found or loaded.")
        self.udt_text.config(state=tk.DISABLED)
    def _display_source(self, source_string):
        self._clear_text_widget(self.source_text)
        self._append_to_text_widget(self.source_text, source_string)
    def _display_results(self, tags):
        self._clear_text_widget(self.tags_text)
        self._append_to_text_widget(self.tags_text, "\n".join(tags))
    def _clear_text_widget(self, widget):
        widget.config(state=tk.NORMAL)
        widget.delete('1.0', tk.END)
        widget.config(state=tk.DISABLED)
    def _append_to_text_widget(self, widget, text, tag=None):
        widget.config(state=tk.NORMAL)
        if tag:
            widget.tag_configure(tag, foreground=tag)
            widget.insert(tk.END, text, tag)
        else:
            widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)
        widget.see(tk.END)
    def _on_closing(self):
        if self.processing_thread and self.processing_thread.is_alive():
            if messagebox.askokcancel("Quit", "A task is still running. Do you want to quit anyway?"):
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    app_root = tk.Tk()
    SclUdtResolverApp(app_root)
    app_root.mainloop()

if __name__ == "__main__":
    main()