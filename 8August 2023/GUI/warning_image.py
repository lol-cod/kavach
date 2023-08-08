import tkinter as tk

def show_warning_message():
    popup = tk.Toplevel()
    popup.title("Warning")
    popup.configure(bg="red")
    
    message = "Suspicious Activity Detected!"
    label = tk.Label(popup, text=message, fg="black", bg="red")
    label.pack(padx=80, pady=20)
    
    warning_label = tk.Label(popup, text="⚠️", font=("Arial", 40), fg="black", bg="red")
    warning_label.pack()
    
    close_button = tk.Button(popup, text="OK", command=popup.destroy)
    close_button.pack(pady=25)

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    show_warning_message()
    
    root.mainloop()
