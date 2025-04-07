import hashlib
import json
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime
import base64
import threading
from tkinter import font as tkfont

# ====================== MODERN THEME ======================
BG_COLOR = "#2d2d2d"
TEXT_COLOR = "#ffffff"
PRIMARY_COLOR = "#5865F2"
SECONDARY_COLOR = "#4e5458"
ACCENT_COLOR = "#eb459e"
ENTRY_BG = "#40444b"
BTN_HOVER = "#4752c4"

class Block:
    def __init__(self, index, timestamp, sender, recipient, encrypted_msg, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.sender = sender
        self.recipient = recipient
        self.encrypted_msg = encrypted_msg
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "recipient": self.recipient,
            "encrypted_msg": self.encrypted_msg,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block mined: {self.hash}")

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2

    def create_genesis_block(self):
        return Block(0, datetime.now().isoformat(), "System", "System", "Genesis", "0")

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def get_latest_block(self):
        return self.chain[-1]

class User:
    def __init__(self, username, password):
        self.username = username
        self.password_hash = self._hash_password(password)
        self._generate_keys()

    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def encrypt_message(self, message, recipient_public_key):
        try:
            encrypted = recipient_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"🔒 Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_msg):
        try:
            encrypted_bytes = base64.b64decode(encrypted_msg.encode('utf-8'))
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"🔓 Successfully decrypted message for {self.username}")
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"🔒❌ Decryption failed for {self.username}: {e}")
            return None

class MessagingSystem:
    def __init__(self):
        self.blockchain = Blockchain()
        self.users = {}
        self._load_users()

    def register_user(self, username, password):
        if username in self.users:
            return False, "Username already exists"
        self.users[username] = User(username, password)
        self._save_users()
        return True, "Registration successful"

    def authenticate_user(self, username, password):
        user = self.users.get(username)
        if not user:
            return False
        return user.password_hash == hashlib.sha256(password.encode()).hexdigest()

    def send_message(self, sender, recipient, message):
        if recipient not in self.users:
            return False, "Recipient not found"
        
        print(f"\n🔐 Encrypting message from {sender} to {recipient}...")
        encrypted_msg = self.users[sender].encrypt_message(
            message, 
            self.users[recipient].public_key
        )
        
        if not encrypted_msg:
            return False, "Encryption failed"
        
        print(f"✅ Message encrypted successfully!")
        print(f"⛏️ Adding block to blockchain...")
        
        new_block = Block(
            index=len(self.blockchain.chain),
            timestamp=datetime.now().isoformat(),
            sender=sender,
            recipient=recipient,
            encrypted_msg=encrypted_msg,
            previous_hash=self.blockchain.get_latest_block().hash
        )
        
        self.blockchain.add_block(new_block)
        return True, "Message sent and added to blockchain!"

    def get_received_messages(self, username):
        messages = []
        for block in self.blockchain.chain[1:]:  # Skip genesis
            if block.recipient == username:
                print(f"\n🔍 Found message for {username} in block {block.index}")
                decrypted = self.users[username].decrypt_message(block.encrypted_msg)
                if decrypted:
                    messages.append({
                        "sender": block.sender,
                        "timestamp": block.timestamp,
                        "message": decrypted,
                        "block_hash": block.hash[:8] + "...",
                        "is_received": True
                    })
        return messages

    def get_sent_messages(self, username, recipient):
        messages = []
        for block in self.blockchain.chain[1:]:
            if block.sender == username and block.recipient == recipient:
                messages.append({
                    "sender": username,
                    "timestamp": block.timestamp,
                    "message": f"(Encrypted) {block.encrypted_msg[:20]}...",
                    "block_hash": block.hash[:8] + "...",
                    "is_received": False
                })
        return messages

    def _save_users(self):
        users_data = {}
        for username, user in self.users.items():
            users_data[username] = {
                "password_hash": user.password_hash,
                "private_key": user.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8'),
                "public_key": user.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            }
        
        with open("users.json", "w") as f:
            json.dump(users_data, f)

    def _load_users(self):
        if not os.path.exists("users.json"):
            return
            
        with open("users.json", "r") as f:
            users_data = json.load(f)
        
        for username, data in users_data.items():
            user = User(username, "temp")
            user.password_hash = data["password_hash"]
            user.private_key = serialization.load_pem_private_key(
                data["private_key"].encode(),
                password=None
            )
            user.public_key = serialization.load_pem_public_key(
                data["public_key"].encode()
            )
            self.users[username] = user

class BlockchainMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Blockchain Messenger")
        self.root.geometry("1000x700")
        self.root.configure(bg=BG_COLOR)
        
        self.title_font = tkfont.Font(family="Helvetica", size=16, weight="bold")
        self.btn_font = tkfont.Font(family="Helvetica", size=10)
        self.msg_font = tkfont.Font(family="Helvetica", size=11)
        
        self.messaging_system = MessagingSystem()
        self.current_user = None
        self.selected_user = None
        
        self._setup_ui()
        self._create_console()
    
    def _setup_ui(self):
        self.login_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(
            self.login_frame, 
            text="Secure Blockchain Messenger", 
            font=self.title_font,
            bg=BG_COLOR,
            fg=TEXT_COLOR
        ).grid(row=0, column=0, columnspan=2, pady=20)
        
        tk.Label(
            self.login_frame, 
            text="Username:", 
            bg=BG_COLOR,
            fg=TEXT_COLOR
        ).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        
        self.username_entry = tk.Entry(
            self.login_frame, 
            bg=ENTRY_BG, 
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR
        )
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(
            self.login_frame, 
            text="Password:", 
            bg=BG_COLOR,
            fg=TEXT_COLOR
        ).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        
        self.password_entry = tk.Entry(
            self.login_frame, 
            show="*", 
            bg=ENTRY_BG, 
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR
        )
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        btn_frame = tk.Frame(self.login_frame, bg=BG_COLOR)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        self.login_btn = tk.Button(
            btn_frame,
            text="Login",
            command=self._login,
            bg=PRIMARY_COLOR,
            fg=TEXT_COLOR,
            activebackground=BTN_HOVER,
            activeforeground=TEXT_COLOR,
            relief="flat",
            font=self.btn_font,
            padx=15
        )
        self.login_btn.pack(side="left", padx=5)
        
        self.register_btn = tk.Button(
            btn_frame,
            text="Register",
            command=self._register,
            bg=SECONDARY_COLOR,
            fg=TEXT_COLOR,
            activebackground=SECONDARY_COLOR,
            activeforeground=TEXT_COLOR,
            relief="flat",
            font=self.btn_font,
            padx=15
        )
        self.register_btn.pack(side="left", padx=5)
        
        self.password_entry.bind("<Return>", lambda e: self._login())
    
    def _create_console(self):
        self.console = scrolledtext.ScrolledText(
            self.root,
            height=10,
            bg="#1e1e1e",
            fg="#00ff00",
            state="disabled",
            font=("Consolas", 9)
        )
        self.console.pack(side="bottom", fill="x", padx=10, pady=10)
    
    def _log_to_console(self, message):
        self.console.config(state="normal")
        self.console.insert("end", message + "\n")
        self.console.config(state="disabled")
        self.console.see("end")
    
    def _show_messaging_ui(self):
        self.login_frame.destroy()
        
        self.main_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.main_frame.pack(fill="both", expand=True)
        
        left_panel = tk.Frame(self.main_frame, width=250, bg=SECONDARY_COLOR)
        left_panel.pack(side="left", fill="y")
        
        user_header = tk.Frame(left_panel, bg=SECONDARY_COLOR, height=70)
        user_header.pack(fill="x", pady=(0, 10))
        
        tk.Label(
            user_header,
            text=f"Logged in as:\n{self.current_user}",
            bg=SECONDARY_COLOR,
            fg=TEXT_COLOR,
            font=self.btn_font
        ).pack(pady=10)
        
        btn_frame = tk.Frame(left_panel, bg=SECONDARY_COLOR)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        self.refresh_btn = tk.Button(
            btn_frame,
            text="🔄 Refresh",
            command=self._refresh_users,
            bg=PRIMARY_COLOR,
            fg=TEXT_COLOR,
            activebackground=BTN_HOVER,
            font=self.btn_font,
            relief="flat"
        )
        self.refresh_btn.pack(side="left", fill="x", expand=True, padx=5)
        
        self.logout_btn = tk.Button(
            btn_frame,
            text="🚪 Logout",
            command=self._logout,
            bg=ACCENT_COLOR,
            fg=TEXT_COLOR,
            activebackground="#ff2b7d",
            font=self.btn_font,
            relief="flat"
        )
        self.logout_btn.pack(side="left", fill="x", expand=True, padx=5)
        
        search_frame = tk.Frame(left_panel, bg=SECONDARY_COLOR)
        search_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.search_entry = tk.Entry(
            search_frame,
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR
        )
        self.search_entry.pack(fill="x", padx=5, pady=5)
        self.search_entry.bind("<KeyRelease>", self._filter_users)
        
        self.users_listbox = tk.Listbox(
            left_panel,
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            selectbackground=PRIMARY_COLOR,
            selectforeground=TEXT_COLOR,
            font=self.btn_font,
            borderwidth=0,
            highlightthickness=0
        )
        self.users_listbox.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.users_listbox.bind("<<ListboxSelect>>", self._select_user)
        
        right_panel = tk.Frame(self.main_frame, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True)
        
        self.chat_header = tk.Frame(right_panel, height=70, bg=BG_COLOR)
        self.chat_header.pack(fill="x")
        
        self.recipient_label = tk.Label(
            self.chat_header,
            text="Select a user to chat",
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            font=self.title_font
        )
        self.recipient_label.pack(side="left", padx=20, pady=10)
        
        self.chat_canvas = tk.Canvas(right_panel, bg=BG_COLOR, highlightthickness=0)
        self.chat_scroll = ttk.Scrollbar(right_panel, orient="vertical", command=self.chat_canvas.yview)
        self.chat_scroll.pack(side="right", fill="y")
        
        self.chat_canvas.configure(yscrollcommand=self.chat_scroll.set)
        self.chat_canvas.pack(fill="both", expand=True)
        
        self.chat_frame = tk.Frame(self.chat_canvas, bg=BG_COLOR)
        self.chat_window = self.chat_canvas.create_window(
            (0, 0),
            window=self.chat_frame,
            anchor="nw"
        )
        
        self.chat_canvas.bind("<Configure>", self._on_canvas_configure)
        self.chat_frame.bind("<Configure>", self._on_frame_configure)
        
        input_frame = tk.Frame(right_panel, bg=BG_COLOR)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.message_entry = tk.Text(
            input_frame,
            height=3,
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR,
            font=self.msg_font,
            wrap="word"
        )
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self._on_enter_pressed)
        
        self.send_btn = tk.Button(
            input_frame,
            text="Send",
            command=self._send_message,
            bg=PRIMARY_COLOR,
            fg=TEXT_COLOR,
            activebackground=BTN_HOVER,
            font=self.btn_font,
            relief="flat",
            padx=15
        )
        self.send_btn.pack(side="right", fill="y")
        
        self._refresh_users()
    
    def _on_canvas_configure(self, event):
        self.chat_canvas.itemconfig(self.chat_window, width=event.width)
    
    def _on_frame_configure(self, event):
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
    
    def _on_enter_pressed(self, event):
        if event.state == 0x4:  # Ctrl key pressed
            self.message_entry.insert("insert", "\n")
            return "break"
        else:
            self._send_message()
            return "break"
    
    def _refresh_users(self):
        self.users_listbox.delete(0, "end")
        for user in self.messaging_system.users:
            if user != self.current_user:
                self.users_listbox.insert("end", user)
        self._log_to_console("✅ User list refreshed")
    
    def _filter_users(self, event):
        search_term = self.search_entry.get().lower()
        self.users_listbox.delete(0, "end")
        
        for user in self.messaging_system.users:
            if user != self.current_user and search_term in user.lower():
                self.users_listbox.insert("end", user)
    
    def _select_user(self, event):
        if not self.users_listbox.curselection():
            return
            
        self.selected_user = self.users_listbox.get(self.users_listbox.curselection())
        self.recipient_label.config(text=f"Chat with: {self.selected_user}")
        self._display_messages()
        self._log_to_console(f"👤 Selected user: {self.selected_user}")
    
    def _display_messages(self):
        for widget in self.chat_frame.winfo_children():
            widget.destroy()
        
        if not self.selected_user:
            return
            
        received = self.messaging_system.get_received_messages(self.current_user)
        received = [msg for msg in received if msg["sender"] == self.selected_user]
        
        sent = self.messaging_system.get_sent_messages(self.current_user, self.selected_user)
        
        all_messages = sorted(received + sent, key=lambda x: x["timestamp"])
        
        for msg in all_messages:
            self._create_message_bubble(
                msg["sender"],
                msg["message"],
                msg["timestamp"],
                msg.get("block_hash", ""),
                msg["is_received"]
            )
        
        self.chat_canvas.yview_moveto(1)
    
    def _create_message_bubble(self, sender, message, timestamp, block_hash, is_received):
        bubble_frame = tk.Frame(self.chat_frame, bg=BG_COLOR)
        bubble_frame.pack(fill="x", padx=10, pady=2)
        
        if sender == self.current_user:
            bubble = tk.Frame(bubble_frame, bg=PRIMARY_COLOR, padx=10, pady=5)
            bubble.pack(anchor="e", padx=20)
            
            tk.Label(
                bubble,
                text=message,
                bg=PRIMARY_COLOR,
                fg=TEXT_COLOR,
                font=self.msg_font,
                justify="left",
                wraplength=400
            ).pack(anchor="e")
            
            meta_frame = tk.Frame(bubble, bg=PRIMARY_COLOR)
            meta_frame.pack(anchor="e")
            
            tk.Label(
                meta_frame,
                text=timestamp,
                bg=PRIMARY_COLOR,
                fg=TEXT_COLOR,
                font=("Helvetica", 8)
            ).pack(side="left", padx=(0, 5))
            
            if block_hash:
                tk.Label(
                    meta_frame,
                    text=f"Block: {block_hash}",
                    bg=PRIMARY_COLOR,
                    fg=TEXT_COLOR,
                    font=("Helvetica", 8)
                ).pack(side="left")
        else:
            bubble = tk.Frame(bubble_frame, bg=ENTRY_BG, padx=10, pady=5)
            bubble.pack(anchor="w", padx=20)
            
            tk.Label(
                bubble,
                text=sender,
                bg=ENTRY_BG,
                fg=ACCENT_COLOR,
                font=("Helvetica", 10, "bold"),
                justify="left"
            ).pack(anchor="w")
            
            tk.Label(
                bubble,
                text=message,
                bg=ENTRY_BG,
                fg=TEXT_COLOR,
                font=self.msg_font,
                justify="left",
                wraplength=400
            ).pack(anchor="w")
            
            meta_frame = tk.Frame(bubble, bg=ENTRY_BG)
            meta_frame.pack(anchor="w")
            
            tk.Label(
                meta_frame,
                text=timestamp,
                bg=ENTRY_BG,
                fg="#aaaaaa",
                font=("Helvetica", 8)
            ).pack(side="left", padx=(0, 5))
            
            if block_hash:
                tk.Label(
                    meta_frame,
                    text=f"Block: {block_hash}",
                    bg=ENTRY_BG,
                    fg="#aaaaaa",
                    font=("Helvetica", 8)
                ).pack(side="left")
    
    def _send_message(self):
        message = self.message_entry.get("1.0", "end").strip()
        if not message or not self.selected_user:
            return
            
        self._log_to_console(f"✉️ Preparing to send message to {self.selected_user}...")
        
        sending_frame = tk.Frame(self.chat_frame, bg=BG_COLOR)
        sending_frame.pack(fill="x", padx=10, pady=2)
        
        sending_bubble = tk.Frame(sending_frame, bg=SECONDARY_COLOR, padx=10, pady=5)
        sending_bubble.pack(anchor="e", padx=20)
        
        tk.Label(
            sending_bubble,
            text="Sending message...",
            bg=SECONDARY_COLOR,
            fg=TEXT_COLOR,
            font=self.msg_font
        ).pack()
        
        self.chat_canvas.yview_moveto(1)
        self.root.update()
        
        def send_thread():
            success, status = self.messaging_system.send_message(
                self.current_user,
                self.selected_user,
                message
            )
            
            self.root.after(0, lambda: self._after_send(success, status, sending_frame))
        
        threading.Thread(target=send_thread, daemon=True).start()
    
    def _after_send(self, success, status, sending_frame):
        sending_frame.destroy()
        
        if success:
            self.message_entry.delete("1.0", "end")
            self._display_messages()
            self._log_to_console("✅ " + status)
        else:
            self._log_to_console("❌ " + status)
            messagebox.showerror("Error", status)
    
    def _login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        self._log_to_console(f"🔐 Attempting login for {username}...")
        
        if self.messaging_system.authenticate_user(username, password):
            self.current_user = username
            self._log_to_console(f"✅ Login successful! Welcome {username}")
            self._show_messaging_ui()
        else:
            self._log_to_console("❌ Login failed: Invalid credentials")
            messagebox.showerror("Error", "Invalid credentials")
    
    def _register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        self._log_to_console(f"📝 Registering new user: {username}")
        
        success, message = self.messaging_system.register_user(username, password)
        if success:
            self._log_to_console(f"✅ {message}")
            messagebox.showinfo("Success", message)
        else:
            self._log_to_console(f"❌ {message}")
            messagebox.showerror("Error", message)
    
    def _logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self._log_to_console(f"👋 Logging out {self.current_user}")
            self.current_user = None
            self.main_frame.destroy()
            self._setup_ui()

def main():
    root = tk.Tk()
    app = BlockchainMessengerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()