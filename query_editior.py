import tkinter
from tkinter import ttk
from tkinter import messagebox
from scrolledframe import ScrolledFrame

def STIG_tk(vuln, stig, check, config, rule):

    def enter_data():
        with open('test.txt', 'w') as test:
            test.write(cust_config_entry.get("1.0", 'end-1c')) 
        root.destroy()
        
        # global config
        # config = cust_config_entry.get()
        # return config
    
    
    root = tkinter.Tk()
    width= root.winfo_screenwidth()               
    height= root.winfo_screenheight()               
    root.geometry("%dx%d" % (width, height))
    root.title("STIG NQE Creator")

    window = ScrolledFrame(root)
    window.pack(fill='both', expand=True)

    frame = tkinter.Frame(window.inner)
    frame.grid(row=0, column=0, sticky='ew')

    user_info_frame =tkinter.LabelFrame(frame, text="STIG Information")
    user_info_frame.grid(row= 0, column=0, padx=10, pady=5)

    rule_title = tkinter.Label(user_info_frame, text="Rule Title: {}".format(rule), wraplength=width-75)
    rule_title.grid(row=1, columnspan=2, sticky='w')
    vuln_id_label = tkinter.Label(user_info_frame, text="Vuln ID: {}".format(vuln))
    vuln_id_label.grid(row=0, column=0)
    stig_id_label = tkinter.Label(user_info_frame, text="STIG ID: {}".format(stig))
    stig_id_label.grid(row=0, column=1)

    check_content_label = tkinter.Label(user_info_frame, text="Check Content:")
    check_content_label.grid(row=2, columnspan=2, sticky='w')
    check_content_data = tkinter.Label(user_info_frame, text=check, justify="left", wraplength=width-75)    
    check_content_data.grid(row=3, columnspan=2, sticky='w')

    for widget in user_info_frame.winfo_children():
        widget.grid_configure(padx=10, pady=5)
    
    frame2 = tkinter.Frame(window.inner)
    frame2.grid(row=1, column=0, sticky='ew')

    config_info_frame =tkinter.LabelFrame(frame2, text="Variables")
    config_info_frame.grid(row= 0, column=1, padx=10, pady=5)

    example_config = tkinter.Label(config_info_frame, text="Example:")
    example_config.grid(row=0, column=0)
    example_config_text = tkinter.Label(config_info_frame, text=config, justify="left")
    example_config_text.grid(row=1, column=0)

    cust_config_label = tkinter.Label(config_info_frame, text="Device Config:\nNote: When adding config, maintain spacing between sections")
    cust_config_label.grid(row=0, column=1)
    cust_config_entry = tkinter.Text(config_info_frame)
    cust_config_entry.grid(row=1, column=1)


    next = tkinter.Button(config_info_frame, text="Next", command=root.destroy )
    next.grid(row=6, column=0)
    
    replace = tkinter.Button(config_info_frame, text="Replace", command=enter_data)
    replace.grid(row=6, column=1)

    for widget in config_info_frame.winfo_children():
        widget.grid_configure(padx=10, pady=5)

    root.mainloop()

def cust_config():
    with open('test.txt', 'r') as fle:
        return fle.read()

def clear_test():
    with open('test.txt', 'w') as fle:
        fle.write('')
    
if __name__ == "__main__":
    STIG_tk('1234', 'cisc-l2', 'loooooooooooong long long test text text', 'k', 'l')