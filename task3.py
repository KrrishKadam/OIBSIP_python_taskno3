"""
Random Password Generator - Command Line & GUI Version
Features: Customizable length, character types, security rules, clipboard support
"""

import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import re


# Character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
AMBIGUOUS = "il1Lo0O"  # Characters that look similar


def generate_password(length=16, use_lower=True, use_upper=True, 
                      use_digits=True, use_symbols=True, 
                      exclude_ambiguous=False, exclude_chars=""):
    """Generate a random password based on criteria"""
    
    # Build character pool
    chars = ""
    required = []
    
    if use_lower:
        chars += LOWERCASE
        required.append(random.choice(LOWERCASE))
    if use_upper:
        chars += UPPERCASE
        required.append(random.choice(UPPERCASE))
    if use_digits:
        chars += DIGITS
        required.append(random.choice(DIGITS))
    if use_symbols:
        chars += SYMBOLS
        required.append(random.choice(SYMBOLS))
    
    if not chars:
        return None
    
    # Remove excluded characters
    if exclude_ambiguous:
        for c in AMBIGUOUS:
            chars = chars.replace(c, "")
    
    for c in exclude_chars:
        chars = chars.replace(c, "")
    
    if not chars:
        return None
    
    # Generate password
    if length <= len(required):
        password = required[:length]
    else:
        password = required + [random.choice(chars) for _ in range(length - len(required))]
    
    random.shuffle(password)
    return "".join(password)


def check_strength(password):
    """Check password strength and return score (0-5) with feedback"""
    score = 0
    feedback = []
    
    # Length checks
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")
    
    if len(password) >= 12:
        score += 1
    
    if len(password) >= 16:
        score += 1
    
    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
    
    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    
    if variety >= 3:
        score += 1
    else:
        feedback.append("Mix uppercase, lowercase, numbers, and symbols")
    
    if variety == 4:
        score += 1
    
    # Determine strength label
    if score <= 1:
        strength = "Very Weak"
        color = "#e74c3c"
    elif score == 2:
        strength = "Weak"
        color = "#e67e22"
    elif score == 3:
        strength = "Medium"
        color = "#f1c40f"
    elif score == 4:
        strength = "Strong"
        color = "#2ecc71"
    else:
        strength = "Very Strong"
        color = "#27ae60"
    
    return score, strength, color, feedback


# ==================== COMMAND LINE VERSION ====================

def cli_generator():
    """Command-line password generator"""
    print("\n" + "=" * 45)
    print("       RANDOM PASSWORD GENERATOR (CLI)")
    print("=" * 45)
    
    while True:
        print("\nOptions:")
        print("1. Generate password")
        print("2. Check password strength")
        print("3. Quit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == "1":
            # Get length
            try:
                length = int(input("Password length (8-128) [16]: ").strip() or "16")
                if length < 4 or length > 128:
                    print("Error: Length must be between 4 and 128")
                    continue
            except ValueError:
                print("Error: Invalid number")
                continue
            
            # Get character options
            print("\nInclude character types (y/n):")
            use_lower = input("  Lowercase (a-z) [y]: ").strip().lower() != 'n'
            use_upper = input("  Uppercase (A-Z) [y]: ").strip().lower() != 'n'
            use_digits = input("  Numbers (0-9) [y]: ").strip().lower() != 'n'
            use_symbols = input("  Symbols (!@#$...) [y]: ").strip().lower() != 'n'
            exclude_amb = input("  Exclude ambiguous (il1Lo0O) [n]: ").strip().lower() == 'y'
            exclude_chars = input("  Exclude specific chars []: ").strip()
            
            # Generate
            password = generate_password(
                length, use_lower, use_upper, use_digits, use_symbols,
                exclude_amb, exclude_chars
            )
            
            if password:
                score, strength, _, _ = check_strength(password)
                print("\n" + "-" * 45)
                print(f"Generated Password: {password}")
                print(f"Strength: {strength} ({score}/5)")
                print("-" * 45)
                
                # Generate alternatives
                print("\nAlternatives:")
                for i in range(3):
                    alt = generate_password(length, use_lower, use_upper, use_digits, use_symbols, exclude_amb, exclude_chars)
                    print(f"  {i+1}. {alt}")
            else:
                print("Error: Could not generate password with given criteria")
        
        elif choice == "2":
            password = input("Enter password to check: ")
            score, strength, _, feedback = check_strength(password)
            print(f"\nStrength: {strength} ({score}/5)")
            if feedback:
                print("Suggestions:")
                for tip in feedback:
                    print(f"  - {tip}")
        
        elif choice == "3":
            break
    
    print("\nGoodbye!")


# ==================== GUI VERSION ====================

class PasswordGeneratorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Generator")
        self.root.geometry("500x550")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f5f5")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the GUI"""
        # Title
        title = tk.Label(
            self.root, text="Password Generator",
            font=("Arial", 22, "bold"), bg="#f5f5f5", fg="#2c3e50"
        )
        title.pack(pady=20)
        
        # Length frame
        length_frame = tk.Frame(self.root, bg="#f5f5f5")
        length_frame.pack(fill="x", padx=40)
        
        tk.Label(
            length_frame, text="Password Length:",
            font=("Arial", 11), bg="#f5f5f5"
        ).pack(side="left")
        
        self.length_var = tk.IntVar(value=16)
        self.length_label = tk.Label(
            length_frame, text="16",
            font=("Arial", 11, "bold"), bg="#f5f5f5", width=3
        )
        self.length_label.pack(side="right")
        
        self.length_slider = ttk.Scale(
            self.root, from_=4, to=64, variable=self.length_var,
            orient="horizontal", length=400,
            command=lambda v: self.length_label.config(text=str(int(float(v))))
        )
        self.length_slider.pack(pady=5)
        
        # Options frame
        options_frame = tk.LabelFrame(
            self.root, text="Character Types",
            font=("Arial", 10), bg="#f5f5f5", padx=20, pady=10
        )
        options_frame.pack(fill="x", padx=40, pady=15)
        
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=True)
        self.ambiguous_var = tk.BooleanVar(value=False)
        
        tk.Checkbutton(
            options_frame, text="Lowercase (a-z)",
            variable=self.lower_var, bg="#f5f5f5", font=("Arial", 10)
        ).grid(row=0, column=0, sticky="w", pady=2)
        
        tk.Checkbutton(
            options_frame, text="Uppercase (A-Z)",
            variable=self.upper_var, bg="#f5f5f5", font=("Arial", 10)
        ).grid(row=0, column=1, sticky="w", pady=2)
        
        tk.Checkbutton(
            options_frame, text="Numbers (0-9)",
            variable=self.digit_var, bg="#f5f5f5", font=("Arial", 10)
        ).grid(row=1, column=0, sticky="w", pady=2)
        
        tk.Checkbutton(
            options_frame, text="Symbols (!@#$...)",
            variable=self.symbol_var, bg="#f5f5f5", font=("Arial", 10)
        ).grid(row=1, column=1, sticky="w", pady=2)
        
        tk.Checkbutton(
            options_frame, text="Exclude Ambiguous (il1Lo0O)",
            variable=self.ambiguous_var, bg="#f5f5f5", font=("Arial", 10)
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
        
        # Exclude chars
        exclude_frame = tk.Frame(self.root, bg="#f5f5f5")
        exclude_frame.pack(fill="x", padx=40)
        
        tk.Label(
            exclude_frame, text="Exclude Characters:",
            font=("Arial", 10), bg="#f5f5f5"
        ).pack(side="left")
        
        self.exclude_entry = tk.Entry(exclude_frame, width=20, font=("Arial", 10))
        self.exclude_entry.pack(side="left", padx=10)
        
        # Generate button
        gen_btn = tk.Button(
            self.root, text="Generate Password",
            font=("Arial", 13, "bold"), bg="#3498db", fg="white",
            width=20, height=2, cursor="hand2",
            command=self.generate
        )
        gen_btn.pack(pady=20)
        
        # Result frame
        result_frame = tk.Frame(self.root, bg="#f5f5f5")
        result_frame.pack(fill="x", padx=40)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            result_frame, textvariable=self.password_var,
            font=("Consolas", 14), justify="center",
            state="readonly", readonlybackground="white", width=35
        )
        self.password_entry.pack(side="left", ipady=8)
        
        copy_btn = tk.Button(
            result_frame, text="📋", font=("Arial", 14),
            width=3, cursor="hand2", command=self.copy_to_clipboard
        )
        copy_btn.pack(side="left", padx=5)
        
        # Strength indicator
        strength_frame = tk.Frame(self.root, bg="#f5f5f5")
        strength_frame.pack(fill="x", padx=40, pady=15)
        
        tk.Label(
            strength_frame, text="Strength:",
            font=("Arial", 10), bg="#f5f5f5"
        ).pack(side="left")
        
        self.strength_label = tk.Label(
            strength_frame, text="",
            font=("Arial", 10, "bold"), bg="#f5f5f5"
        )
        self.strength_label.pack(side="left", padx=10)
        
        # Strength bar
        self.strength_canvas = tk.Canvas(
            self.root, width=400, height=20, bg="#ddd", highlightthickness=0
        )
        self.strength_canvas.pack()
        
        # History
        history_frame = tk.LabelFrame(
            self.root, text="Recent Passwords",
            font=("Arial", 10), bg="#f5f5f5", padx=10, pady=5
        )
        history_frame.pack(fill="x", padx=40, pady=15)
        
        self.history_listbox = tk.Listbox(
            history_frame, height=4, font=("Consolas", 10),
            selectmode="single"
        )
        self.history_listbox.pack(fill="x")
        self.history_listbox.bind("<Double-Button-1>", self.copy_from_history)
        
        tk.Label(
            history_frame, text="Double-click to copy",
            font=("Arial", 8), bg="#f5f5f5", fg="#888"
        ).pack()
    
    def generate(self):
        """Generate password"""
        length = self.length_var.get()
        
        password = generate_password(
            length=length,
            use_lower=self.lower_var.get(),
            use_upper=self.upper_var.get(),
            use_digits=self.digit_var.get(),
            use_symbols=self.symbol_var.get(),
            exclude_ambiguous=self.ambiguous_var.get(),
            exclude_chars=self.exclude_entry.get()
        )
        
        if password:
            self.password_var.set(password)
            
            # Update strength
            score, strength, color, _ = check_strength(password)
            self.strength_label.config(text=strength, fg=color)
            
            # Update strength bar
            self.strength_canvas.delete("all")
            bar_width = (score / 5) * 400
            self.strength_canvas.create_rectangle(0, 0, bar_width, 20, fill=color, outline="")
            
            # Add to history
            self.history_listbox.insert(0, password)
            if self.history_listbox.size() > 10:
                self.history_listbox.delete(10)
        else:
            messagebox.showerror("Error", "Select at least one character type")
    
    def copy_to_clipboard(self):
        """Copy password to clipboard"""
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
            
            # Show feedback
            original_text = self.strength_label.cget("text")
            self.strength_label.config(text="Copied!", fg="#27ae60")
            self.root.after(1500, lambda: self.strength_label.config(text=original_text))
    
    def copy_from_history(self, event):
        """Copy password from history"""
        selection = self.history_listbox.curselection()
        if selection:
            password = self.history_listbox.get(selection[0])
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
            messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()


# ==================== MAIN ====================

def main():
    print("=" * 45)
    print("       RANDOM PASSWORD GENERATOR")
    print("=" * 45)
    print("\n1. Command Line Version")
    print("2. GUI Version")
    
    choice = input("\nChoice (1/2): ").strip()
    
    if choice == "1":
        cli_generator()
    else:
        app = PasswordGeneratorGUI()
        app.run()


if __name__ == "__main__":
    main()
