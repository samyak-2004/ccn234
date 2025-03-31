import tkinter as tk
from tkinter import ttk, messagebox, Canvas
import subprocess
import cv2
import mediapipe as mp
import threading
import networkx as nx
import random
import platform
import os

class IPBlockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gesture-Controlled Network Security Dashboard (Linux)")
        self.root.geometry("1200x900")
        self.root.configure(bg="#f0f8f0")
        
        # Style Configuration
        self.style = ttk.Style()
        self.style.configure('TFrame', background="#f0f8f0")
        self.style.configure('TLabel', background="#f0f8f0", font=('Helvetica', 12))
        self.style.configure('TButton', font=('Helvetica', 12), padding=5)
        self.style.map('Green.TButton',
                      foreground=[('active', 'black'), ('!disabled', 'black')],
                      background=[('active', '#45a049'), ('!disabled', '#4CAF50')])
        
        # MediaPipe setup
        self.mp_hands = mp.solutions.hands
        self.hands = self.mp_hands.Hands(max_num_hands=2)
        self.mp_drawing = mp.solutions.drawing_utils
        
        # Camera setup
        self.camera_running = False
        self.cap = None
        
        # Network visualization
        self.network_graph = nx.Graph()
        self.selected_node = None
        self.dragging = False
        self.zoom_level = 1.0
        self.canvas_center = (600, 450)
        
        # Security rules and blocked IPs
        self.security_rules = []
        self.blocked_ips = set()  # Track blocked IPs
        
        # GUI elements
        self.create_widgets()
        self.create_network_visualization()
        
        # Gesture control variables
        self.block_gesture = "THUMBS_DOWN"
        self.unblock_gesture = "THUMBS_UP"
        self.last_action = None
        self.current_gesture = "NONE"
        self.finger_touch_active = False
        
        # Initialize iptables check for Linux
        if platform.system() == "Linux":
            self.check_iptables_installed()
            self.load_blocked_ips()
        
    def check_iptables_installed(self):
        """Check if iptables is available on the system"""
        try:
            subprocess.run(["which", "iptables"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "iptables not found. Please install iptables to use this application.", parent=self.root)
            self.root.after(100, self.root.destroy)
    
    def load_blocked_ips(self):
        """Load currently blocked IPs from iptables"""
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "INPUT", "-n", "-v"],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.splitlines():
                if "DROP" in line:
                    parts = line.split()
                    # The source IP is typically the 8th field in the output
                    if len(parts) > 7 and parts[7].count('.') == 3:
                        self.blocked_ips.add(parts[7])
                        self.update_log(f"Loaded blocked IP from iptables: {parts[7]}")
            
        except subprocess.CalledProcessError as e:
            self.update_log(f"Error loading iptables rules: {e.stderr}")
    
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel for controls
        control_frame = ttk.Frame(main_frame, width=300)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Right panel for network visualization
        vis_frame = ttk.Frame(main_frame)
        vis_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Network canvas with scrollbars
        self.canvas_frame = ttk.Frame(vis_frame)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.canvas_xscroll = ttk.Scrollbar(self.canvas_frame, orient=tk.HORIZONTAL)
        self.canvas_yscroll = ttk.Scrollbar(self.canvas_frame, orient=tk.VERTICAL)
        self.network_canvas = Canvas(self.canvas_frame, bg="white", highlightthickness=0,
                                    xscrollcommand=self.canvas_xscroll.set,
                                    yscrollcommand=self.canvas_yscroll.set,
                                    scrollregion=(0, 0, 2000, 2000))
        
        self.canvas_xscroll.config(command=self.network_canvas.xview)
        self.canvas_yscroll.config(command=self.network_canvas.yview)
        
        self.network_canvas.grid(row=0, column=0, sticky="nsew")
        self.canvas_yscroll.grid(row=0, column=1, sticky="ns")
        self.canvas_xscroll.grid(row=1, column=0, sticky="ew")
        self.canvas_frame.grid_rowconfigure(0, weight=1)
        self.canvas_frame.grid_columnconfigure(0, weight=1)
        
        # Header
        header = ttk.Frame(control_frame)
        header.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(header, text="Linux Network Security Dashboard", 
                 font=('Helvetica', 16, 'bold')).pack(side=tk.LEFT)
        
        # IP Address Entry
        ip_frame = ttk.Frame(control_frame)
        ip_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(ip_frame, text="IP Address:", font=('Helvetica', 14)).pack(side=tk.LEFT, padx=5)
        self.ip_entry = ttk.Entry(ip_frame, width=20, font=('Helvetica', 14))
        self.ip_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        # Action Buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=15)
        
        self.block_btn = ttk.Button(btn_frame, text="Block IP", 
                                  style='Green.TButton', command=self.block_ip)
        self.block_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        self.unblock_btn = ttk.Button(btn_frame, text="Unblock IP", 
                                    style='Green.TButton', command=self.unblock_ip)
        self.unblock_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        # Advanced iptables controls for Linux
        if platform.system() == "Linux":
            adv_frame = ttk.Frame(control_frame)
            adv_frame.pack(fill=tk.X, pady=15)
            
            ttk.Label(adv_frame, text="Advanced iptables:", 
                     font=('Helvetica', 14)).pack(anchor=tk.W)
            
            self.flush_btn = ttk.Button(adv_frame, text="Flush Rules",
                                     style='Green.TButton', command=self.flush_iptables)
            self.flush_btn.pack(fill=tk.X, pady=5)
            
            self.save_btn = ttk.Button(adv_frame, text="Save Rules",
                                     style='Green.TButton', command=self.save_iptables)
            self.save_btn.pack(fill=tk.X, pady=5)
            
            self.restore_btn = ttk.Button(adv_frame, text="Restore Rules",
                                        style='Green.TButton', command=self.restore_iptables)
            self.restore_btn.pack(fill=tk.X, pady=5)
        
        # Network Controls
        network_control_frame = ttk.Frame(control_frame)
        network_control_frame.pack(fill=tk.X, pady=15)
        
        ttk.Label(network_control_frame, text="Network Controls:", 
                 font=('Helvetica', 14)).pack(anchor=tk.W)
        
        self.add_node_btn = ttk.Button(network_control_frame, text="Add Node",
                                     style='Green.TButton', command=self.add_random_node)
        self.add_node_btn.pack(fill=tk.X, pady=5)
        
        self.add_rule_btn = ttk.Button(network_control_frame, text="Draw Security Rule",
                                      style='Green.TButton', command=self.toggle_rule_drawing)
        self.add_rule_btn.pack(fill=tk.X, pady=5)
        
        # Zoom Controls
        zoom_frame = ttk.Frame(control_frame)
        zoom_frame.pack(fill=tk.X, pady=15)
        
        ttk.Label(zoom_frame, text="Zoom:", font=('Helvetica', 14)).pack(anchor=tk.W)
        
        self.zoom_in_btn = ttk.Button(zoom_frame, text="Zoom In",
                                     style='Green.TButton', command=lambda: self.adjust_zoom(1.2))
        self.zoom_in_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        self.zoom_out_btn = ttk.Button(zoom_frame, text="Zoom Out",
                                      style='Green.TButton', command=lambda: self.adjust_zoom(0.8))
        self.zoom_out_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        # Gesture Control
        gesture_frame = ttk.Frame(control_frame)
        gesture_frame.pack(fill=tk.X, pady=15)
        
        self.gesture_toggle = ttk.Button(gesture_frame, text="Start Gesture Control", 
                                       style='Green.TButton', command=self.toggle_gesture_control)
        self.gesture_toggle.pack(fill=tk.X)
        
        self.gesture_label = ttk.Label(gesture_frame, text="Current Gesture: None", 
                                      font=('Helvetica', 12))
        self.gesture_label.pack(fill=tk.X, pady=5)
        
        # Status
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(status_frame, text="Status:", font=('Helvetica', 14)).pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, text="Ready", font=('Helvetica', 14, 'bold'))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Log Area
        log_frame = ttk.Frame(control_frame)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(log_frame, text="Activity Log:", font=('Helvetica', 14)).pack(anchor=tk.W)
        
        self.log_text = tk.Text(log_frame, height=10, width=30, 
                              font=('Helvetica', 12), bg="black", fg="white",
                              padx=10, pady=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        self.log_text.insert(tk.END, "System ready. Enter an IP address to begin.\n")
        
        # Bind network canvas events
        self.network_canvas.bind("<Button-1>", self.on_canvas_click)
        self.network_canvas.bind("<B1-Motion>", self.on_canvas_drag)
        self.network_canvas.bind("<ButtonRelease-1>", self.on_canvas_release)
        self.network_canvas.bind("<MouseWheel>", self.on_mousewheel)
        
    def create_network_visualization(self):
        """Initialize the network visualization with sample nodes and connections"""
        # Add some initial nodes
        for i in range(5):
            x = random.randint(100, 1100)
            y = random.randint(100, 800)
            self.network_graph.add_node(f"Node_{i}", x=x, y=y, ip=f"192.168.1.{i+1}")
        
        # Add some initial connections
        for i in range(4):
            self.network_graph.add_edge(f"Node_{i}", f"Node_{(i+1)%4}")
        
        self.draw_network()
    
    def draw_network(self):
        """Draw the network graph on the canvas with current zoom level"""
        self.network_canvas.delete("all")
        
        # Draw edges first
        for u, v in self.network_graph.edges():
            ux, uy = self.network_graph.nodes[u]['x'], self.network_graph.nodes[u]['y']
            vx, vy = self.network_graph.nodes[v]['x'], self.network_graph.nodes[v]['y']
            
            # Apply zoom transformation
            zx1, zy1 = self.apply_zoom(ux, uy)
            zx2, zy2 = self.apply_zoom(vx, vy)
            
            self.network_canvas.create_line(zx1, zy1, zx2, zy2, fill="gray", width=2)
        
        # Draw security rules
        for rule in self.security_rules:
            x1, y1, x2, y2 = rule['coords']
            zx1, zy1 = self.apply_zoom(x1, y1)
            zx2, zy2 = self.apply_zoom(x2, y2)
            
            self.network_canvas.create_line(zx1, zy1, zx2, zy2, fill="red", width=3, dash=(5, 2))
            self.network_canvas.create_text((zx1+zx2)/2, (zy1+zy2)/2, 
                                          text=rule['type'], fill="red")
        
        # Draw nodes on top
        for node in self.network_graph.nodes():
            x = self.network_graph.nodes[node]['x']
            y = self.network_graph.nodes[node]['y']
            ip = self.network_graph.nodes[node]['ip']
            
            # Apply zoom transformation
            zx, zy = self.apply_zoom(x, y)
            radius = 20 * self.zoom_level
            
            color = "green" if not self.is_ip_blocked(ip) else "red"
            
            self.network_canvas.create_oval(zx-radius, zy-radius, zx+radius, zy+radius, 
                                          fill=color, outline="black")
            self.network_canvas.create_text(zx, zy, text=node.split('_')[1], fill="white")
            self.network_canvas.create_text(zx, zy+30*self.zoom_level, text=ip, 
                                          font=('Helvetica', int(8*self.zoom_level)))
        
        # Update scroll region
        self.update_scroll_region()
    
    def apply_zoom(self, x, y):
        """Apply zoom transformation to coordinates"""
        # Calculate position relative to center
        rel_x = x - self.canvas_center[0]
        rel_y = y - self.canvas_center[1]
        
        # Apply zoom
        zx = self.canvas_center[0] + rel_x * self.zoom_level
        zy = self.canvas_center[1] + rel_y * self.zoom_level
        
        return zx, zy
    
    def update_scroll_region(self):
        """Update the scroll region based on current nodes and zoom level"""
        if not self.network_graph.nodes():
            return
            
        # Get all node positions
        xs = [self.network_graph.nodes[n]['x'] for n in self.network_graph.nodes()]
        ys = [self.network_graph.nodes[n]['y'] for n in self.network_graph.nodes()]
        
        # Calculate min/max with padding
        min_x, max_x = min(xs) - 100, max(xs) + 100
        min_y, max_y = min(ys) - 100, max(ys) + 100
        
        # Apply zoom to scroll region
        z_min_x, z_min_y = self.apply_zoom(min_x, min_y)
        z_max_x, z_max_y = self.apply_zoom(max_x, max_y)
        
        self.network_canvas.config(scrollregion=(z_min_x, z_min_y, z_max_x, z_max_y))
    
    def adjust_zoom(self, factor):
        """Adjust the zoom level by the given factor"""
        self.zoom_level *= factor
        self.zoom_level = max(0.1, min(3.0, self.zoom_level))  # Limit zoom range
        self.draw_network()
    
    def on_mousewheel(self, event):
        """Handle mouse wheel events for zooming"""
        if event.delta > 0:
            self.adjust_zoom(1.1)
        else:
            self.adjust_zoom(0.9)
    
    def add_random_node(self):
        """Add a random node to the network"""
        new_id = len(self.network_graph.nodes())
        x = random.randint(100, 1100)
        y = random.randint(100, 800)
        ip = f"192.168.1.{new_id+1}"
        
        self.network_graph.add_node(f"Node_{new_id}", x=x, y=y, ip=ip)
        
        # Connect to a random existing node
        if self.network_graph.nodes():
            random_node = random.choice(list(self.network_graph.nodes()))
            self.network_graph.add_edge(f"Node_{new_id}", random_node)
        
        self.draw_network()
        self.update_log(f"Added new node: Node_{new_id} ({ip})")
    
    def add_node_at_position(self, x, y):
        """Add a new node at the specified position"""
        # Convert screen coordinates to canvas coordinates
        canvas_x = self.network_canvas.canvasx(x)
        canvas_y = self.network_canvas.canvasy(y)
        
        # Convert back to original coordinates considering zoom
        orig_x = self.canvas_center[0] + (canvas_x - self.canvas_center[0]) / self.zoom_level
        orig_y = self.canvas_center[1] + (canvas_y - self.canvas_center[1]) / self.zoom_level
        
        new_id = len(self.network_graph.nodes())
        ip = f"192.168.1.{new_id+1}"
        
        self.network_graph.add_node(f"Node_{new_id}", x=orig_x, y=orig_y, ip=ip)
        
        # Connect to the closest existing node
        if self.network_graph.nodes():
            closest_node = min(self.network_graph.nodes(),
                             key=lambda n: ((self.network_graph.nodes[n]['x'] - orig_x)**2 +
                                          (self.network_graph.nodes[n]['y'] - orig_y)**2))
            self.network_graph.add_edge(f"Node_{new_id}", closest_node)
        
        self.draw_network()
        self.update_log(f"Added new node at ({int(orig_x)}, {int(orig_y)})")
    
    def toggle_rule_drawing(self):
        """Toggle security rule drawing mode"""
        self.drawing_rule = not self.drawing_rule
        if self.drawing_rule:
            self.add_rule_btn.config(text="Cancel Drawing")
            self.update_log("Rule drawing mode enabled - Click two nodes to create a rule")
        else:
            self.add_rule_btn.config(text="Draw Security Rule")
            self.current_drawing_rule = None
            self.update_log("Rule drawing mode disabled")
    
    def on_canvas_click(self, event):
        """Handle canvas click events"""
        if self.drawing_rule:
            # Find if a node was clicked
            clicked_node = None
            for node in self.network_graph.nodes():
                x, y = self.apply_zoom(self.network_graph.nodes[node]['x'], 
                                      self.network_graph.nodes[node]['y'])
                radius = 20 * self.zoom_level
                if (x - event.x)**2 + (y - event.y)**2 <= radius**2:
                    clicked_node = node
                    break
            
            if clicked_node:
                if not self.current_drawing_rule:
                    # First node selected
                    x, y = self.network_graph.nodes[clicked_node]['x'], self.network_graph.nodes[clicked_node]['y']
                    self.current_drawing_rule = {
                        'node1': clicked_node,
                        'x1': x,
                        'y1': y
                    }
                    self.update_log(f"Selected {clicked_node} as first node")
                else:
                    # Second node selected - create rule
                    x, y = self.network_graph.nodes[clicked_node]['x'], self.network_graph.nodes[clicked_node]['y']
                    rule = {
                        'type': "BLOCK" if self.current_gesture == "THUMBS_DOWN" else "ALLOW",
                        'node1': self.current_drawing_rule['node1'],
                        'node2': clicked_node,
                        'coords': (self.current_drawing_rule['x1'], 
                                  self.current_drawing_rule['y1'],
                                  x, y)
                    }
                    self.security_rules.append(rule)
                    self.update_log(f"Created {rule['type']} rule between {rule['node1']} and {rule['node2']}")
                    self.draw_network()
                    self.current_drawing_rule = None
                    self.drawing_rule = False
                    self.add_rule_btn.config(text="Draw Security Rule")
        else:
            # Check if a node was clicked for dragging
            for node in self.network_graph.nodes():
                x, y = self.apply_zoom(self.network_graph.nodes[node]['x'], 
                                      self.network_graph.nodes[node]['y'])
                radius = 20 * self.zoom_level
                if (x - event.x)**2 + (y - event.y)**2 <= radius**2:
                    self.selected_node = node
                    self.dragging = True
                    break
    
    def on_canvas_drag(self, event):
        """Handle canvas drag events"""
        if self.dragging and self.selected_node:
            # Convert screen coordinates to original coordinates considering zoom
            canvas_x = self.network_canvas.canvasx(event.x)
            canvas_y = self.network_canvas.canvasy(event.y)
            orig_x = self.canvas_center[0] + (canvas_x - self.canvas_center[0]) / self.zoom_level
            orig_y = self.canvas_center[1] + (canvas_y - self.canvas_center[1]) / self.zoom_level
            
            # Move the selected node
            self.network_graph.nodes[self.selected_node]['x'] = orig_x
            self.network_graph.nodes[self.selected_node]['y'] = orig_y
            self.draw_network()
    
    def on_canvas_release(self, event):
        """Handle canvas release events"""
        self.dragging = False
        self.selected_node = None
    
    def block_ip(self):
        ip = self.ip_entry.get()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address", parent=self.root)
            return
            
        if platform.system() == "Linux":
            try:
                # Check if rule already exists
                check_cmd = f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null"
                check_result = subprocess.run(check_cmd, shell=True)
                
                if check_result.returncode == 0:
                    self.update_log(f"⚠️ IP {ip} is already blocked")
                    messagebox.showinfo("Info", f"IP {ip} is already blocked", parent=self.root)
                    return
                
                # Add the rule
                subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
                self.blocked_ips.add(ip)
                self.update_log(f"✅ Blocked IP: {ip}")
                self.status_label.config(text=f"Blocked {ip}", foreground="#d32f2f")
            except subprocess.CalledProcessError as e:
                self.update_log(f"❌ Error blocking IP: {e}")
                messagebox.showerror("Error", f"Failed to block IP: {e}\n\nYou may need to run this application with sudo privileges.", parent=self.root)
        
        self.draw_network()
            
    def unblock_ip(self):
        ip = self.ip_entry.get()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address", parent=self.root)
            return
            
        if platform.system() == "Linux":
            try:
                # Check if rule exists
                check_cmd = f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null"
                check_result = subprocess.run(check_cmd, shell=True)
                
                if check_result.returncode != 0:
                    self.update_log(f"⚠️ IP {ip} is not currently blocked")
                    messagebox.showinfo("Info", f"IP {ip} is not currently blocked", parent=self.root)
                    return
                
                # Remove the rule
                subprocess.run(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True, check=True)
                self.blocked_ips.discard(ip)
                self.update_log(f"✅ Unblocked IP: {ip}")
                self.status_label.config(text=f"Unblocked {ip}", foreground="#388e3c")
            except subprocess.CalledProcessError as e:
                self.update_log(f"❌ Error unblocking IP: {e}")
                messagebox.showerror("Error", f"Failed to unblock IP: {e}", parent=self.root)
        
        self.draw_network()
    
    def flush_iptables(self):
        """Flush all iptables rules"""
        if platform.system() != "Linux":
            return
            
        if messagebox.askyesno("Confirm", "This will remove ALL iptables rules. Continue?", parent=self.root):
            try:
                subprocess.run("sudo iptables -F", shell=True, check=True)
                subprocess.run("sudo iptables -X", shell=True, check=True)
                subprocess.run("sudo iptables -t nat -F", shell=True, check=True)
                subprocess.run("sudo iptables -t nat -X", shell=True, check=True)
                subprocess.run("sudo iptables -t mangle -F", shell=True, check=True)
                subprocess.run("sudo iptables -t mangle -X", shell=True, check=True)
                subprocess.run("sudo iptables -P INPUT ACCEPT", shell=True, check=True)
                subprocess.run("sudo iptables -P FORWARD ACCEPT", shell=True, check=True)
                subprocess.run("sudo iptables -P OUTPUT ACCEPT", shell=True, check=True)
                
                self.blocked_ips.clear()
                self.update_log("✅ Flushed all iptables rules")
                self.status_label.config(text="Flushed all rules", foreground="#d32f2f")
            except subprocess.CalledProcessError as e:
                self.update_log(f"❌ Error flushing iptables: {e}")
                messagebox.showerror("Error", f"Failed to flush iptables: {e}", parent=self.root)
    
    def save_iptables(self):
        """Save current iptables rules to a file"""
        if platform.system() != "Linux":
            return
            
        try:
            # Create rules directory if it doesn't exist
            rules_dir = os.path.expanduser("~/.iptables_rules")
            if not os.path.exists(rules_dir):
                os.makedirs(rules_dir)
            
            # Save rules to file
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            rules_file = os.path.join(rules_dir, f"iptables_rules_{timestamp}.rules")
            
            with open(rules_file, "w") as f:
                subprocess.run("sudo iptables-save", shell=True, check=True, stdout=f)
            
            self.update_log(f"✅ Saved iptables rules to {rules_file}")
            self.status_label.config(text="Rules saved", foreground="#388e3c")
        except subprocess.CalledProcessError as e:
            self.update_log(f"❌ Error saving iptables rules: {e}")
            messagebox.showerror("Error", f"Failed to save iptables rules: {e}", parent=self.root)
        except Exception as e:
            self.update_log(f"❌ Error saving iptables rules: {e}")
            messagebox.showerror("Error", f"Failed to save iptables rules: {e}", parent=self.root)
    
    def restore_iptables(self):
        """Restore iptables rules from a file"""
        if platform.system() != "Linux":
            return
            
        try:
            # Find the most recent rules file
            rules_dir = os.path.expanduser("~/.iptables_rules")
            if not os.path.exists(rules_dir):
                self.update_log("⚠️ No saved rules found")
                messagebox.showinfo("Info", "No saved rules found", parent=self.root)
                return
                
            # Get all .rules files sorted by modification time
            rules_files = sorted(
                [f for f in os.listdir(rules_dir) if f.endswith('.rules')],
                key=lambda x: os.path.getmtime(os.path.join(rules_dir, x)),
                reverse=True
            )
            
            if not rules_files:
                self.update_log("⚠️ No saved rules found")
                messagebox.showinfo("Info", "No saved rules found", parent=self.root)
                return
                
            # Restore the most recent file
            rules_file = os.path.join(rules_dir, rules_files[0])
            subprocess.run(f"sudo iptables-restore < {rules_file}", shell=True, check=True)
            
            # Reload blocked IPs
            self.blocked_ips.clear()
            self.load_blocked_ips()
            
            self.update_log(f"✅ Restored iptables rules from {rules_file}")
            self.status_label.config(text="Rules restored", foreground="#388e3c")
        except subprocess.CalledProcessError as e:
            self.update_log(f"❌ Error restoring iptables rules: {e}")
            messagebox.showerror("Error", f"Failed to restore iptables rules: {e}", parent=self.root)
        except Exception as e:
            self.update_log(f"❌ Error restoring iptables rules: {e}")
            messagebox.showerror("Error", f"Failed to restore iptables rules: {e}", parent=self.root)
    
    def is_ip_blocked(self, ip):
        """Check if an IP is blocked"""
        if platform.system() == "Linux":
            return ip in self.blocked_ips
        else:
            return False
    
    def update_log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
    
    def toggle_gesture_control(self):
        if self.camera_running:
            self.camera_running = False
            self.gesture_toggle.config(text="Start Gesture Control")
            self.update_log("Gesture control stopped")
            if self.cap:
                self.cap.release()
        else:
            self.camera_running = True
            self.gesture_toggle.config(text="Stop Gesture Control")
            self.update_log("Gesture control started - Show gestures to interact")
            threading.Thread(target=self.run_gesture_control, daemon=True).start()
    
    def run_gesture_control(self):
        self.cap = cv2.VideoCapture(0)
        
        while self.camera_running:
            ret, frame = self.cap.read()
            if not ret:
                continue
                
            frame = cv2.flip(frame, 1)
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            results = self.hands.process(rgb_frame)
            
            if results.multi_hand_landmarks:
                for hand_landmarks in results.multi_hand_landmarks:
                    self.mp_drawing.draw_landmarks(
                        frame, hand_landmarks, self.mp_hands.HAND_CONNECTIONS)
                    
                    gesture = self.detect_gesture(hand_landmarks)
                    self.current_gesture = gesture
                    self.root.after(0, lambda: self.gesture_label.config(
                        text=f"Current Gesture: {gesture.replace('_', ' ')}"))
                    
                    # Handle gestures
                    if gesture == self.block_gesture and self.last_action != "block":
                        ip = self.ip_entry.get()
                        if ip:
                            self.root.after(0, self.block_ip)
                            self.last_action = "block"
                    elif gesture == self.unblock_gesture and self.last_action != "unblock":
                        ip = self.ip_entry.get()
                        if ip:
                            self.root.after(0, self.unblock_ip)
                            self.last_action = "unblock"
                    elif gesture == "PINCH":
                        # Handle pinch zoom
                        index_tip = hand_landmarks.landmark[self.mp_hands.HandLandmark.INDEX_FINGER_TIP]
                        thumb_tip = hand_landmarks.landmark[self.mp_hands.HandLandmark.THUMB_TIP]
                        current_distance = ((index_tip.x - thumb_tip.x)**2 + 
                                         (index_tip.y - thumb_tip.y)**2)**0.5
                        
                        if hasattr(self, 'last_pinch_distance'):
                            zoom_factor = 1 + (self.last_pinch_distance - current_distance) * 2
                            self.root.after(0, lambda: self.adjust_zoom(zoom_factor))
                        
                        self.last_pinch_distance = current_distance
                    elif gesture == "TOUCH":
                        # Handle finger touch to add node
                        if not self.finger_touch_active:
                            self.finger_touch_active = True
                            # Get touch position (approximate center of hand)
                            wrist = hand_landmarks.landmark[self.mp_hands.HandLandmark.WRIST]
                            # Convert to screen coordinates (simplified)
                            screen_x = int(wrist.x * self.network_canvas.winfo_width())
                            screen_y = int(wrist.y * self.network_canvas.winfo_height())
                            self.root.after(0, lambda: self.add_node_at_position(screen_x, screen_y))
                    elif gesture == "NONE":
                        self.last_action = None
                        self.finger_touch_active = False
                        if hasattr(self, 'last_pinch_distance'):
                            del self.last_pinch_distance
            
            cv2.imshow('Gesture Control (Press Q to close)', frame)
            
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
                
        self.cap.release()
        cv2.destroyAllWindows()
        self.camera_running = False
        self.gesture_toggle.config(text="Start Gesture Control")
        self.root.after(0, lambda: self.update_log("Gesture control stopped"))
        self.root.after(0, lambda: self.gesture_label.config(text="Current Gesture: None"))
    
    def detect_gesture(self, landmarks):
        """Detect hand gestures from landmarks"""
        thumb_tip = landmarks.landmark[self.mp_hands.HandLandmark.THUMB_TIP]
        index_tip = landmarks.landmark[self.mp_hands.HandLandmark.INDEX_FINGER_TIP]
        middle_tip = landmarks.landmark[self.mp_hands.HandLandmark.MIDDLE_FINGER_TIP]
        ring_tip = landmarks.landmark[self.mp_hands.HandLandmark.RING_FINGER_TIP]
        pinky_tip = landmarks.landmark[self.mp_hands.HandLandmark.PINKY_TIP]
        
        # Check for touch gesture (index finger extended, others closed)
        index_extended = index_tip.y < middle_tip.y - 0.1
        others_closed = (middle_tip.y > ring_tip.y + 0.1 and 
                        ring_tip.y > pinky_tip.y + 0.1 and
                        thumb_tip.y > index_tip.y + 0.1)
        
        if index_extended and others_closed:
            return "TOUCH"
        
        # Check for pinch gesture (thumb and index finger close)
        thumb_index_dist = ((thumb_tip.x - index_tip.x)**2 + (thumb_tip.y - index_tip.y)**2)**0.5
        if thumb_index_dist < 0.05:
            return "PINCH"
        
        # Check for thumbs up/down
        if thumb_tip.y < index_tip.y - 0.1 and thumb_tip.y < middle_tip.y - 0.1:
            return "THUMBS_UP"
        elif thumb_tip.y > index_tip.y + 0.1 and thumb_tip.y > middle_tip.y + 0.1:
            return "THUMBS_DOWN"
        
        return "NONE"
    
    def on_closing(self):
        if self.camera_running:
            self.camera_running = False
            if self.cap:
                self.cap.release()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = IPBlockerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
