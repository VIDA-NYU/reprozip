import os
import subprocess
try:
    import Tkinter as tk
except ImportError:
    import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import yaml
import math
from tkinter import messagebox


# Run 0 being the first run
numberOfRuns = 0
#to keep a check on which was the last window visited, -1 saying no widnows prior
flag = -1


class ReprozipApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self._frame = None
        self.switch_frame(TraceWindow)
        self.title("ReproZip")
        self.tk_setPalette(background= '#6E53BE')
        self.resizable(False,False)
        self.geometry("450x400")
        self.filepath ="config.yml"
        
    def switch_frame(self, frame_class):
        """Destroys current frame and replaces it with a new one."""
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.grid(padx = 50, pady = 50)


class TraceWindow(tk.Frame):

    def __init__(self, master):
        self.tempPath = tk.StringVar()
        tk.Frame.__init__(self, master)
        self.tempPath.set("Set working directory using Browse")
        default = tk.StringVar(self, value= "run " + str(numberOfRuns) )
        # Entry widget for entering the name
        self.master.runName = tk.Entry(self, textvariable = default, bg = "white", width= "18", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
        self.master.runName.focus_set()
        self.master.runName.grid(row = 0, column=1,  sticky = "nsew" )
        # Asking for the Name of Run
        labelRunName = tk.Label(self, text = "Name of Run",  font = "Helvetica 14", width = "15")
        labelRunName.grid(row = 0, column = 0, sticky = "nsew", padx = (30,0))
        # Textbox for Terminal using Text
        textTerminal = tk.Text(self, width = "40",height = "8", fg="black" )
        textTerminal.grid(row = 2, columnspan = 2, pady = (20,0) ,sticky = "nsew", padx = (30,0))
        # Browse button
        browseButton = tk.Button(self, text="Browse",command = self._askopenfile, highlightbackground="#404040", highlightthickness="0",fg='white', height ="2", width = "8")
        browseButton.grid(row = 4, pady = (20,0), sticky = "nw", padx = (30,0))
        # Display file path
        workDir = tk.Label(self, textvariable =self.tempPath, fg="white", font = "Helvetica 11 italic", width ="40")
        workDir.grid(row = 3, columnspan = 2, pady = (20,0),sticky = "nsew", padx = (30,0))
        # Trace button
        traceButton = tk.Button(self, text="Trace", command= self._reproTrace,highlightbackground="#404040", highlightthickness="0",fg='white', height ="2", width = "8")
        traceButton.grid(row = 4, column =1, pady = (20,0), sticky = "ne")
        
    def _askopenfile(self):
        path = tk.filedialog.askopenfilename()
        self.tempPath.set(path)
        #print(self.master.runName.get())
        
    def _reproTrace(self):
        tempCommand = "ls"
        p_status = subprocess.Popen(tempCommand, stdout=subprocess.PIPE, shell=True)
        (output, err) = p_status.communicate()  
        #This makes the wait possible
        p_status.wait()
        global flag
        flag = 0
        self.master.switch_frame(AddRunWindow)

class AddRunWindow(tk.Frame):
    
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        # Button for adding a new run 
        addRunButton = tk.Button(self, text = "Add Run", command= self._addRun, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "10")
        addRunButton.grid(row = 1, column =2, padx= (40,0))
        # Button to edit configuration window 
        nextButton = tk.Button(self, text=" Next ", command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "10")
        nextButton.grid(row = 3, column =2 ,padx= (40,0))
        # Label for naming runs
        runLabel = tk. Label(self, text = "Existing Runs",  font = "Helvetica 14")
        runLabel.grid(row = 0, column =0, sticky= "nw", pady = (10,5))
        # to read the runs from yaml file
        with open(self.master.filepath) as fr:
            data = yaml.safe_load(fr)  
           
        if(flag != 3):
        #if data['runs'][numberOfRuns]['id'] == "run "+ str(numberOfRuns) :
            data['runs'][numberOfRuns]['id'] = self.master.runName.get()
            with open("config.yml", "w") as fw:
                yaml.safe_dump(data, fw)
                
        # Listbox to display existing runs
        runsList = tk.Listbox(self, bg = "white", fg= "black", width=23, height=12,font = "Helvetica 14")
        # Output the read run id to the GUI 
        for i in range(0, numberOfRuns+1):
            runsList.insert(tk.END, data['runs'][i]['id'])
        runsList.grid(row = 1, rowspan =3, columnspan = 2, sticky= "nw")

    def _addRun(self):
        global numberOfRuns
        numberOfRuns = numberOfRuns + 1 
        # print(numberOfRuns)
        global flag
        flag = 1
        self.master.switch_frame(TraceWindow)
           
class editConfigurationWindow(tk.Frame):
      
    def __init__(self, master):
        tk.Frame.__init__(self, master)  
        self.image = tk.PhotoImage(file = "back.png")
        # button to go back to Add Run Window
        backButton = tk.Button(self, text = "Back", image = self.image,  command = self._back, height ="10", width = "30")
        backButton.grid(row =0, column = 0, sticky = "nw")
        # button to Rename input/output files
        renameButton = tk.Button(self, text= "Rename I/O Files", command = lambda : master.switch_frame(renameFilesWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "13")
        renameButton.grid(row =2, column = 0)
        # button to switch to add/remove files window
        addFilesButton = tk.Button(self, text = "Add/Remove Files",  command = lambda: master.switch_frame(AddFilesWindow) , highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "13")
        addFilesButton.grid(row =2, column =3)
        # button to go back to Add Run Wind
        proceedButton = tk.Button(self, text = "Proceed",  command = lambda : master.switch_frame(PackWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "14")
        proceedButton.grid(row =3, column = 2, pady = (60,0))
        # Label for showing Trace Successfull
        traceSuccessfulLabel = tk.Label(self, text = "Trace Successfull !",font = "Helvetica 17", fg = "white" )
        traceSuccessfulLabel.grid(row =1, column = 0, columnspan = 3,pady= (30, 50), sticky = "e")

    def _back(self):
        global flag
        flag = 3
        self.master.switch_frame(AddRunWindow)

class renameFilesWindow(tk.Frame):
 
    def __init__(self, master):
        tk.Frame.__init__(self, master)  
        #Label for input/output files 
        ioFilesLabel = tk.Label(self, text = "Input/Output Files", fg="white", font = "Helvetica 14")
        ioFilesLabel.grid(row= 0, column =0, sticky ="nw")
        # Label for Rename As
        renameLabel = tk.Label(self, text = "Rename As", fg="white", font = "Helvetica 14")
        renameLabel.grid(row = 1, column = 2, rowspan=2,  sticky ="nw", padx=(10,0))
        # Button to rename the file
        confirmButton = tk.Button(self, text = "Confirm",command = self._rename, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        confirmButton.grid(row = 4, column = 2,padx=(10,0) )
        # Button to Proceed
        proceedButton = tk.Button(self, text = "Back",command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        proceedButton.grid(row = 8, column = 2, padx=(10,0))
        
        self.index = tk.StringVar(self,value= " ")
        self.varEntry= tk.StringVar(self,value= "Select file from list")
        # entry for changing file name
        self.fileNameEntry = tk.Entry(self, textvariable = self.varEntry, bg = "white", width= "19", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
        self.fileNameEntry.grid(row = 2, column = 2, padx=(10,0))
    
        self.vsb = tk.Scrollbar(self,orient=tk.VERTICAL)
        self.vsb.grid(row = 1, column = 1,sticky = "ns", rowspan = 10 )
        self.hsb = tk.Scrollbar(self,orient=tk.HORIZONTAL)
        self.hsb.grid(row = 11, column = 0,sticky = "ew", rowspan = 10 )
        
        # Listbox to display the input and output files
        self.iofilesListbox = tk.Listbox(self, yscrollcommand=lambda f, l: self.autoscroll(self.vsb, f, l),
    xscrollcommand=lambda f, l: self.autoscroll(self.hsb, f, l), bg = "white", fg= "black", font = "Helvetica 15", width=20, height=13)
        self.iofilesListbox.bind('<<ListboxSelect>>', self._onSelect)
        self.iofilesListbox.grid(row = 1, column = 0, sticky = "nsew", rowspan = 10)
        self._writeList()

        self.vsb['command'] = self.iofilesListbox.yview
        self.hsb['command'] = self.iofilesListbox.xview
        
    def autoscroll(self,sbar, first, last):
        # Hide and show scrollbar as needed
        first, last = float(first), float(last)
        if first <= 0 and last >= 1:
            sbar.grid_remove()
        else:
            sbar.grid()
        sbar.set(first, last)
        
    def _onSelect(self,event):
        w = event.widget
        with open(self.master.filepath) as fr:
            data = yaml.safe_load(fr)   
        if(w.curselection()):
            self.index = int(w.curselection()[0])
            self.varEntry.set(data['inputs_outputs'][self.index]['name'])
            self.fileNameEntry.focus_set()
            
    def _writeList(self):
        with open(self.master.filepath) as fr:
            data = yaml.safe_load(fr) 
        # looping through the config file for input and output
        for i in range(0, len(data['inputs_outputs'])):
            prefix = ""
            if data['inputs_outputs'][i]['read_by_runs']:
                prefix += "[I]"
            
            if data['inputs_outputs'][i]['written_by_runs']:
                prefix += "[O]"
            
            prefix += " "
            prefix += data['inputs_outputs'][i]['name'] 
            self.iofilesListbox.insert(tk.END, prefix)
  
    def _rename(self):
        with open(self.master.filepath) as fr:
            data = yaml.safe_load(fr) 
     
        data['inputs_outputs'][self.index]['name'] = self.fileNameEntry.get()
        with open(self.master,filepath, "w") as fw:
            yaml.safe_dump(data, fw)
        
        self.iofilesListbox.delete(0,tk.END)
        self._writeList()

class AddFilesWindow(tk.Frame):
    
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.filepath = ".reprozip-trace/config.yml"
        AddRemoveLabel = tk.Label(self, text = "Add/Remove Files",  font = "Helvetica 14")
        AddRemoveLabel.grid(row = 0, sticky= "nsew", padx=(20,0))
        
        backButton = tk.Button(self, text = "Back",command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        backButton.grid(row = 3, sticky= "n", pady=(20,0), padx=(20,0))
        
        t = CheckboxTreeview(self, show="tree")
        t.grid(row = 1, sticky= "nsew", pady=(10,0), padx=(20,0))

class CheckboxTreeview(ttk.Treeview): 
    
    def __init__(self, master, **kw):
        ttk.Treeview.__init__(self, master, columns=("fullpath", "type"),displaycolumns="")

        # checkboxes are implemented with pictures
        self.im_checked = tk.PhotoImage(file='checked.png')
        self.im_unchecked = tk.PhotoImage(file='unchecked.png')
        self.im_tristate = tk.PhotoImage(file='tristate.png')
        self.tag_configure("unchecked", image=self.im_unchecked)
        self.tag_configure("tristate", image=self.im_tristate)
        self.tag_configure("checked", image=self.im_checked)
        
        self.alreadyExists = tk.StringVar()
        self.alreadyExists = "0"

        with open(self.master.filepath) as fr:
            self.data = yaml.safe_load(fr) 
            
        self.heading("#0", text="Directory Structure")
        self.column("#0", stretch=1, width=300)
        # check / uncheck boxes on click
        self.bind("<Button-1>", self.box_click, True)
        self.populate_roots()
        self.bind('<<TreeviewOpen>>', self.update_tree)

    def checkInConfigfile(self,p): 
        if(p in self.data["other_files"]):
            self.alreadyExists = "1"
        elif any(i['path'] == p for i in self.data["inputs_outputs"]):
            self.alreadyExists = "1"
        else:
            self.alreadyExists = "0" 
        for i in range(len(self.data["packages"])):
            if p in self.data["packages"][i]["files"]:
                self.alreadyExists = "1"
       
    def populate_roots(self):
        dir = os.path.expanduser('/')
        node = self._insert('', 'end', text=dir, values=[dir, "directory"])
        self.populate_tree(node)

    def populate_tree(self, node):
        if self.set(node, "type") != 'directory':
            return
        path = self.set(node, "fullpath")
        self.delete(*self.get_children(node))
        parent = self.parent(node)
        
        for p in os.listdir(path):
            ptype = None
            p = os.path.join(path, p).replace('\\', '/')
            if os.path.isdir(p): ptype = "directory"
            elif os.path.isfile(p): ptype = "file"
    
            fname = os.path.split(p)[1]
            self.checkInConfigfile(p)
            id = self._insert(node, "end", text=fname, values=[p, ptype])
            if ptype == 'directory':
                self._insert(id, 0 ,text="dummy")
                self.item(id, text=fname)

    def update_tree(self,event):
        tree = event.widget
        self.populate_tree(tree.focus())

    def _insert(self, parent, index, iid=None, **kw): 
        if not "tags" in kw:
            kw["tags"] = ("unchecked",)
        elif not ("unchecked" in kw["tags"] or "checked" in kw["tags"]
                  or "tristate" in kw["tags"]):
            kw["tags"] = ("unchecked",)           
        item = ttk.Treeview.insert(self, parent, index, iid, **kw)
        if (self.alreadyExists == "1"):
            self.check_ancestor(item)
            self.check_descendant(item)    
        return item

    def check_descendant(self, item):
        #check the boxes of item's descendants 
        children = self.get_children(item)
        for iid in children:
            self.item(iid, tags=("checked",))
            self.check_descendant(iid)

    def check_ancestor(self, item):
        # check the box of item and change the state of the boxes of item's ancestors accordingly 
        self.item(item, tags=("checked",))
        parent = self.parent(item)
        if parent:
            children = self.get_children(parent)
            b = ["checked" in self.item(c, "tags") for c in children]
            if False in b:
                # at least one box is not checked and item's box is checked
                self.tristate_parent(parent)
            else:
                # all boxes of the children are checked
                self.check_ancestor(parent)

    def tristate_parent(self, item):
        # put the box of item in tristate and change the state of the boxes of item's ancestors accordingly 
        self.item(item, tags=("tristate",))
        parent = self.parent(item)
        if parent:
            self.tristate_parent(parent)

    def uncheck_descendant(self, item):
        # uncheck the boxes of item's descendant
        children = self.get_children(item)
        for iid in children:
            self.item(iid, tags=("unchecked",))
            self.uncheck_descendant(iid)

    def uncheck_ancestor(self, item):
        # uncheck the box of item and change the state of the boxes of item's ancestors accordingly 
        self.item(item, tags=("unchecked",))
        parent = self.parent(item)
        if parent:
            children = self.get_children(parent)
            b = ["unchecked" in self.item(c, "tags") for c in children]
            if False in b:
                # at least one box is checked and item's box is unchecked
                self.tristate_parent(parent)
            else:
                # no box is checked
                self.uncheck_ancestor(parent)
                
    def removingFiles(self, pathToRemove):
        if((pathToRemove[0]) in self.data["other_files"]):
            self.data["other_files"].remove(pathToRemove[0])
        for i in range(len(self.data["packages"])):
            if pathToRemove[0] in self.data["packages"][i]["files"]:
                self.data["packages"][i]['files'].remove(pathToRemove[0])
        for i in range(len(self.data["inputs_outputs"])):
            if self.data["inputs_outputs"][i]["path"] == pathToRemove[0]:
                self.data["inputs_outputs"][i]["path"]= None 

    def box_click(self, event):
        #check or uncheck box when clicked#
        x, y, widget = event.x, event.y, event.widget
        elem = widget.identify("element", x, y)
        if "image" in elem:
            # a box was clicked
            item = self.identify_row(y)
            tags = self.item(item, "tags")
            pathToAdd = self.item(item, "values")
            
            if ("unchecked" in tags) or ("tristate" in tags):
                self.check_ancestor(item)
                self.check_descendant(item)
                if(pathToAdd[1] == "directory"):
                     children = self.get_children(item)
                     for iid in children:
                         childToAdd = self.item(iid, "values")
                         self.data["other_files"].append(childToAdd[0])
                else:
                    self.data["other_files"].append(pathToAdd[0])

            else:
                self.uncheck_descendant(item)
                self.uncheck_ancestor(item)
                
                if(pathToAdd[1] == "directory"):
                    children = self.get_children(item) 
                    for iid in children:
                        childToRemove = self.item(iid, "values")
                        self.removingFiles(childToRemove)
       
                elif (pathToAdd[1] == "file"):
                    self.removingFiles(pathToAdd)      
 
            with open(self.master.filepath, "w") as fw:
                yaml.safe_dump(self.data, fw)

class PackWindow(tk.Frame):
    
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.rpzFileName = tk.StringVar(self, value= ".rpz")
        #Label to ask for the RPZ package name        
        Namelabel = tk.Label(self, text = "Name the RPZ Package as",  font = "Helvetica 14")
        Namelabel.grid(row =0, sticky="nsew", padx=(80,0))
        #button to confirm the name
        SaveAsbutton = tk.Button(self, text = "Pack",command = self.packRpz, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10") 
        SaveAsbutton.grid(row =2, padx=(80,0))
        #Entry box for the name input
        rpzFileNameEntry = tk.Entry(self, textvariable = self.rpzFileName, width= "25", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
        rpzFileNameEntry.grid(row =1, sticky="nsew", padx=(70,0), pady= (10,20))
  
    def packRpz(self):
        try:
            fileName = self.rpzFileName.get()
            size = os.stat(fileName).st_size
            size = self.convert_bytes(size)
            successlabel = tk.Label(self, text = "Successfully Packed!",  font = "Helvetica 17")
            successlabel.grid(row =3, pady=(50, 0), padx=(80,0))
            
            fileSize = tk.StringVar(self, value= "Package size: "+size)
            
            displayName = tk.Label(self, textvariable = self.rpzFileName,  font = "Helvetica 15")
            displayName.grid(row =4, pady=(30, 0), padx=(80,0))
            displaySize = tk.Label(self, textvariable = fileSize,  font = "Helvetica 15")
            displaySize.grid(row =5, padx=(80,0)) 
        
        except os.error:
            messagebox.showerror("Error", "Oops! Something went wrong! \nPlease Try Again!")

    def convert_bytes(self,size):
       if size == 0:
           return "0B"
       size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
       i = int(math.floor(math.log(size, 1024)))
       p = math.pow(1024, i)
       s = round(size / p, 2)
       return "%s %s" % (s, size_name[i])

if __name__ == "__main__":
    app = ReprozipApp()
    app.mainloop()
