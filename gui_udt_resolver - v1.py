# gui_udt_resolver.py
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from pathlib import Path
import sys

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
        self.root.title("SCL UDT-Aware Tag Finder")
        self.root.geometry("1600x900")
        self.parser = Parser()
        self.parser.language = language
        self.udt_dictionary = {}
        self._create_widgets()

    def _create_widgets(self):
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X, side=tk.TOP)

        # --- MODIFIED: Store buttons as instance variables to enable/disable them ---
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

        tags_frame = ttk.Frame(main_pane, padding=5)
        ttk.Label(tags_frame, text="Resolved Tag Paths", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.tags_text = scrolledtext.ScrolledText(tags_frame, wrap=tk.WORD, font=("Consolas", 11), state=tk.DISABLED)
        self.tags_text.pack(fill=tk.BOTH, expand=True)
        main_pane.add(tags_frame, weight=2)
        
        # --- NEW: Add status bar and progress bar at the bottom ---
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 5))
        
        self.progress_bar = ttk.Progressbar(bottom_frame, orient='horizontal', mode='determinate')
        self.progress_bar.pack(fill=tk.X)

        self.status_var = tk.StringVar(value="Ready. Please scan a project folder first.")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5).pack(fill=tk.X, side=tk.BOTTOM)

    # --- NEW: Helper methods to manage the UI state ---
    def _start_processing(self):
        """Disables buttons and sets the cursor to 'wait'."""
        self.root.config(cursor="watch")
        self.scan_button.config(state=tk.DISABLED)
        self.analyze_file_button.config(state=tk.DISABLED)
        self.analyze_folder_button.config(state=tk.DISABLED)
        self.root.update_idletasks() # Force UI to update immediately

    def _end_processing(self):
        """Re-enables buttons, resets cursor and progress bar."""
        self.root.config(cursor="")
        self.scan_button.config(state=tk.NORMAL)
        self.analyze_file_button.config(state=tk.NORMAL)
        self.analyze_folder_button.config(state=tk.NORMAL)
        self.progress_bar['value'] = 0
        self.root.update_idletasks() # Force UI to update immediately
        
    def scan_project_folder(self):
        folder_path = filedialog.askdirectory(title="Select folder containing ALL source files (UDTs and DBs)")
        if not folder_path: return

        self._start_processing() # <-- NEW
        try: # <-- NEW: Use try...finally to ensure UI is always restored
            self.udt_dictionary.clear()
            self.status_var.set(f"Scanning {folder_path} for all type definitions...")
            self.root.update_idletasks()
            
            source_files = list(Path(folder_path).rglob("*.udt")) + list(Path(folder_path).rglob("*.db"))
            if not source_files:
                messagebox.showinfo("No Files Found", "No '.udt' or '.db' files were found in the selected folder.")
                self.status_var.set("Scan complete. No source files found.")
                return

            # --- NEW: Update progress bar for this task too ---
            self.progress_bar['maximum'] = len(source_files)

            for i, file in enumerate(source_files):
                self.status_var.set(f"Scanning {i+1}/{len(source_files)}: {file.name}...")
                self._parse_and_add_udts_from_file(file)
                self.progress_bar['value'] = i + 1
                self.root.update_idletasks() # Keep UI responsive
                
            self._display_udt_dictionary()
            self.udt_status_label.config(text=f"Loaded {len(self.udt_dictionary)} UDTs.", foreground="green")
            self.status_var.set("Type scan complete. Ready to analyze a source file.")
        finally:
            self._end_processing() # <-- NEW

    def _parse_and_add_udts_from_file(self, filepath: Path):
        # ... (this method is unchanged)
        try:
            tree = self.parser.parse(filepath.read_bytes())
            for type_def_node in tree.root_node.children:
                if type_def_node.type == 'type_definition':
                    udt_name_node = type_def_node.child_by_field_name('name')
                    if not udt_name_node: continue
                    udt_name = get_node_text(udt_name_node)
                    if udt_name not in self.udt_dictionary:
                        self.udt_dictionary[udt_name] = []
                    for child in type_def_node.children:
                        if child.type == 'struct_definition':
                            for field_node in child.children:
                                if field_node.type == 'fields':
                                    field_name = get_node_text(field_node.child_by_field_name('name'))
                                    field_type_node = next((c for c in field_node.children if c.type == 'type'), None)
                                    self.udt_dictionary[udt_name].append((field_name, field_type_node))
        except Exception as e:
            print(f"Error parsing file for UDTs {filepath.name}: {e}")

    def analyze_source_file(self, filepath_str=None):
        if not self.udt_dictionary:
            messagebox.showwarning("Warning", "Please scan a project folder first.")
            return
        
        if not filepath_str:
            filepath_str = filedialog.askopenfilename(title="Select a DB, UDT, or SCL file", filetypes=[("Source Files", "*.scl *.udt *.db"), ("All Files", "*.*")])
        
        if not filepath_str: return
        
        self._start_processing() # <-- NEW
        try: # <-- NEW
            filepath = Path(filepath_str)
            self.status_var.set(f"Analyzing {filepath.name}...")
            self.root.update_idletasks()
            
            self._parse_and_add_udts_from_file(filepath)
            self._display_udt_dictionary()
            self.udt_status_label.config(text=f"Loaded {len(self.udt_dictionary)} UDTs.", foreground="green")
            
            source_bytes = filepath.read_bytes()
            self._display_source(source_bytes.decode('utf-8', errors='replace'))
            tree = self.parser.parse(source_bytes)
            
            if tree.root_node.has_error:
                messagebox.showwarning("Parsing Warning", "File contains syntax errors. Results may be incomplete.")
            
            all_tags = self._analyze_file_contents(tree.root_node)
            
            self._display_results(all_tags)
            self.status_var.set(f"Analysis complete. Found {len(all_tags)} resolved tag paths.")
        finally:
            self._end_processing() # <-- NEW

    def analyze_db_folder(self):
        if not self.udt_dictionary:
            messagebox.showwarning("Warning", "Please scan a project folder first to build the type dictionary.")
            return

        folder_path_str = filedialog.askdirectory(title="Select folder containing DB files to analyze")
        if not folder_path_str: return

        self._start_processing() # <-- NEW
        try: # <-- NEW
            folder_path = Path(folder_path_str)
            self.status_var.set(f"Scanning for .db files in {folder_path}...")
            self.root.update_idletasks()
            
            db_files = list(folder_path.rglob("*.db"))
            if not db_files:
                messagebox.showinfo("No Files Found", "No '.db' files were found in the selected folder.")
                self.status_var.set("Batch scan complete. No .db files found.")
                return

            self._display_source("")
            self._display_results([])
            
            all_tags_from_folder = set()
            total_files = len(db_files)
            
            self.progress_bar['maximum'] = total_files # <-- NEW: Set progress bar max value

            for i, filepath in enumerate(db_files):
                self.status_var.set(f"Processing {i+1}/{total_files}: {filepath.name}...")
                self.progress_bar['value'] = i + 1 # <-- NEW: Update progress bar
                self.root.update_idletasks() # <-- IMPORTANT to show progress
                
                try:
                    tree = self.parser.parse(filepath.read_bytes())
                    tags_from_file = self._analyze_file_contents(tree.root_node)
                    all_tags_from_folder.update(tags_from_file)
                except Exception as e:
                    print(f"Failed to process {filepath.name}: {e}")

            self._display_results(sorted(list(all_tags_from_folder)))
            self.status_var.set(f"Batch analysis complete. Found {len(all_tags_from_folder)} total unique tags in {total_files} files.")
        finally:
            self._end_processing() # <-- NEW

    # ... (the rest of the file from _analyze_file_contents downwards is unchanged)
    
    def _analyze_file_contents(self, root_node):
        all_found_tags = set()
        for node in root_node.children:
            if node.type == 'data_block':
                tags_from_db = self._resolve_db_tags(node)
                all_found_tags.update(tags_from_db)
        return all_found_tags

    def _resolve_db_tags(self, db_node):
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
            self._expand_tag(base_path, tag_type_node, resolved_tags)
        return resolved_tags

    def _expand_tag(self, base_path, type_node, resolved_tags):
        if not type_node: return
        struct_def_node = next((c for c in type_node.children if c.type == 'struct_definition'), None)
        if struct_def_node:
            for field_node in struct_def_node.children:
                if field_node.type == 'fields':
                    sub_tag_name = get_node_text(field_node.child_by_field_name('name'))
                    sub_type_node = next((c for c in field_node.children if c.type == 'type'), None)
                    new_base_path = f"{base_path}.{sub_tag_name}"
                    self._expand_tag(new_base_path, sub_type_node, resolved_tags)
            return

        array_def_node = next((c for c in type_node.children if c.type == 'array_type'), None)
        if array_def_node:
            base_type_node_of_array = array_def_node.children[-1]
            dim_nodes = [c for c in array_def_node.children if c.type == 'integer_literal']
            try:
                if len(dim_nodes) == 2:
                    start_index = int(get_node_text(dim_nodes[0]))
                    end_index = int(get_node_text(dim_nodes[1]))
                    for i in range(start_index, end_index + 1):
                        self._expand_tag(f"{base_path}[{i}]", base_type_node_of_array, resolved_tags)
                    return
            except (ValueError, IndexError): pass
            self._expand_tag(f"{base_path}[]", base_type_node_of_array, resolved_tags)
            return

        clean_type_name = get_node_text(type_node)
        if clean_type_name in self.udt_dictionary:
            for sub_tag_name, sub_tag_type_node in self.udt_dictionary[clean_type_name]:
                new_base_path = f"{base_path}.{sub_tag_name}"
                self._expand_tag(new_base_path, sub_tag_type_node, resolved_tags)
        else:
            resolved_tags.add(base_path)

    def _display_udt_dictionary(self):
        self.udt_text.config(state=tk.NORMAL)
        self.udt_text.delete('1.0', tk.END)
        text_to_insert = ""
        for udt_name, fields in sorted(self.udt_dictionary.items()):
            text_to_insert += f"TYPE {udt_name}:\n"
            for field_name, field_type_node in fields:
                field_type_text = get_node_text(field_type_node) if field_type_node else "UNKNOWN"
                text_to_insert += f"  - {field_name}: {field_type_text}\n"
            text_to_insert += "\n"
        self.udt_text.insert('1.0', text_to_insert if text_to_insert else "No UDTs found or loaded.")
        self.udt_text.config(state=tk.DISABLED)

    def _display_source(self, source_string):
        self.source_text.config(state=tk.NORMAL)
        self.source_text.delete('1.0', tk.END)
        self.source_text.insert('1.0', source_string)
        self.source_text.config(state=tk.DISABLED)
        
    def _display_results(self, tags):
        self.tags_text.config(state=tk.NORMAL)
        self.tags_text.delete('1.0', tk.END)
        self.tags_text.insert('1.0', "\n".join(tags))
        self.tags_text.config(state=tk.DISABLED)

def main():
    app_root = tk.Tk()
    SclUdtResolverApp(app_root)
    app_root.mainloop()

if __name__ == "__main__":
    main()