
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
try:
    # for Python2
    import tkinter as tk
    from tkinter import filedialog
    from tkinter import ttk
except ImportError:
    # for Python3
    import Tkinter as tk
    import tkFileDialog as filedialog
    import ttk
import yaml
import math
import sys
import itertools
import tkMessageBox as messagebox
import shutil 


# Run 0 being the first run

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
        self.geometry("650x600")
        #self.filepath ="config.yml"
	self.filepath = ".reprozip-trace/config.yml"

        
    def switch_frame(self, frame_class):
        """Destroys current frame and replaces it with a new one."""
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
	self._frame.grid(padx = 40, pady = 70)



class TraceWindow(tk.Frame):

    def __init__(self, master):
        
        self.tempPath = tk.StringVar()
	self.tempWorkDir = tk.StringVar()
	
	
	if os.path.isdir(".reprozip-trace") and (flag !=1):
		self.messageWindow()


        tk.Frame.__init__(self, master)

        self.tempPath.set("Select your script using Browse")
	self.tempWorkDir.set("Set your working directory using Browse")
	
        default = tk.StringVar(self, value= "run ")
	self.arguments = []

        # Entry widget for entering the name
        self.runName = tk.Entry(self, textvariable = default, bg = "white", width= "15", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
        self.runName.focus_set()
        self.runName.grid(row = 0, column=1, sticky = "nse", columnspan=2)
        
        # For the Name of Run
        labelRunName = tk.Label(self, text = "Name of Run:",  font = "Helvetica 14", width = "20")
        labelRunName.grid(row = 0, column = 0, sticky ="ne")
	
	# For getting Arguments
	labelArgs = tk.Label(self, text = "Arguments:",  font = "Helvetica 14", width = "20")
        labelArgs.grid(row = 1, column = 0, sticky ="ne", pady= (50,0))

	# Entry widget for entering arguments
	self.argumentsEntry = tk.Entry(self, bg = "white", width= "15", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
	self.argumentsEntry.focus_set()
        self.argumentsEntry.grid(row = 1, column=1, sticky = "nsew", columnspan=3, pady= (50,0) )

	# Label for Working Directory 
	labelWorkDir = tk.Label(self, text = "Working Directory:",  font = "Helvetica 14", width = "20")
        labelWorkDir.grid(row = 2, column = 0, sticky ="nse" , pady= (50,0))
        
	# Browse button for Working Directory
        browseButton = tk.Button(self, text="...",command = self._askopendir, highlightbackground="black", highlightthickness="0",fg='white', height ="1", width = "2")
        browseButton.grid(row = 2, column=4, pady= (50,0), sticky = "ne")
	
	# Display WorkDir 
        self.workDir = tk.Entry(self, textvariable =self.tempWorkDir, fg="white", font = "Helvetica 11 italic", width ="40")
        self.workDir.grid(row = 2, column = 2,sticky = "w", columnspan =2,pady= (50,0))

	# Label for selecting the script 
	labelScript = tk.Label(self, text = "Program executable:",  font = "Helvetica 14", width = "20")
        labelScript.grid(row = 3, column = 0, sticky ="nse" , pady= (50,0))

	# Browse button for Script
        browseScriptButton = tk.Button(self, text="...",command = self._askopenfile, highlightbackground="black", highlightthickness="0",fg='white', height ="1", width = "2")
        browseScriptButton.grid(row = 3, column=4, sticky = "ne", pady= (50,0))
       
        # Display Script 
        self.selectedScript = tk.Entry(self, textvariable =self.tempPath, fg="white", font = "Helvetica 11 italic", width ="40")
        self.selectedScript.grid(row = 3, column = 2, columnspan =2, sticky = "w", pady= (50,0))
        
        # Trace button
        traceButton = tk.Button(self, text="Trace", command= self._reproTrace,highlightbackground="#404040", highlightthickness="0",fg='white', height ="2", width = "8")
        traceButton.grid(row = 5, column =1,columnspan =2,  pady = (60,0), padx = (40,0),  sticky = "ne")
	
	self.grid_columnconfigure(0, weight =1)
	self.grid_columnconfigure(1, weight =1)
	self.grid_columnconfigure(2, weight =1)
	self.grid_columnconfigure(3, weight =1)
	self.grid_columnconfigure(4, weight =1)
	self.grid_rowconfigure(0, weight =1)
	self.grid_rowconfigure(1, weight =1)
	self.grid_rowconfigure(2, weight =1)
	self.grid_rowconfigure(3, weight =1)
	self.grid_rowconfigure(4, weight =1)
	self.grid_rowconfigure(5, weight =1)
	
	# for Native terminal
	self.native_escape = self.shell_escape


    def shell_escape(self,s):
	safe_shell_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       "-+=/:.,%_")

    	if not s or any(c not in safe_shell_chars for c in s):
        	return '"%s"' % (s.replace('\\', '\\\\')
        	                  .replace('"', '\\"')
        	                  .replace('`', '\\`')
        	                  .replace('$', '\\$'))
    	else:
        	return s

    def find_command(self,cmd):
	for path in itertools.chain(os.environ.get('PATH', '').split(os.pathsep),['/usr/local/bin']):	      
		filename = os.path.join(path, cmd)
		if os.path.exists(filename):
			print(filename)
	              	return filename
	return None


    def run_in_system_terminal(self,cmd,wait=True, close_on_success=False):
    
    	cmd = ' '.join(self.native_escape(c) for c in cmd)
	# setting default Working Directory
	work_dir = (str(self.tempWorkDir.get()))

    	if not close_on_success:
    		cmd = '/bin/sh -c %s' % \
		self.shell_escape(cmd + ' ; echo "Press enter..."; read r')
    
    	for term, arg_factory in [('konsole', lambda a: ['--nofork', '-e', a]),('gnome-terminal', lambda a: ['--disable-factory-', '--', '/bin/sh', '-c', a]),('lxterminal', lambda a: ['--command=' + a]),('rxvt', lambda a: ['-e', a]),('xterm', lambda a:['-e', a])]:
	    	
		if self.find_command(term) is not None:
	        	args = arg_factory(cmd)
		
			if wait:
                    		returnCode = subprocess.check_call([term] + args,stdin=subprocess.PIPE, cwd = work_dir)
			
                	else:
                	        subprocess.Popen([term] + args, stdin=subprocess.PIPE, cwd = work_dir)
			
			return None
    	return "Couldn't start a terminal", 'critical'

    def _askopendir(self):
        selectedWorkDir = filedialog.askdirectory(initialdir="/",title='Please select a directory')
	if(selectedWorkDir):
		self.tempWorkDir.set(selectedWorkDir)
	else:
		self.tempWorkDir.set("Set your working directory using Browse")
  
    def _askopenfile(self):
        selectedScript = filedialog.askopenfilename()
	if(selectedScript):
		selectedScript = os.path.basename(selectedScript)
		self.tempPath.set(selectedScript)
	else:
		self.tempPath.set("Select your script using Browse")
        #print(self.master.runName.get())
     


    def messageWindow(self):
		
	def deleteDir():
		shutil.rmtree(".reprozip-trace")
		win.destroy()   
	
	def continueTrace():
		with open(self.master.filepath) as fr:
			self.master.data = yaml.safe_load(fr)  
		self.master.switch_frame(AddRunWindow)
		win.destroy()

	win = tk.Toplevel()
	win.title('Warning')
        win.resizable(False,False)
        win.geometry("350x200")

	message1 = "A trace already exists!" 
	message2 = "Select from the options below"
	
	warningLabel = tk.Label(win, text= message1 ,font = "Helvetica 13", width = "20")
        warningLabel.grid(column= 0, row= 0, sticky = "nsew", columnspan = 3, padx =(20,0), pady = (30,0)) 
	
	questionLabel = tk.Label(win, text= message2 ,font = "Helvetica 13", width = "20")
	questionLabel.grid(column= 0, row= 1, sticky = "nsew", columnspan = 3, padx =(10,0), pady = (10,0)) 

	deleteButton = tk.Button(win, text='Delete', command= deleteDir)
	deleteButton.grid(column = 0, row=2, sticky = "nse", padx =(10,0), pady = (20,0))
	appendButton = tk.Button(win, text='Append', command= continueTrace)
	appendButton.grid(column = 2, row=2, sticky = "nsw", padx =(10,0), pady = (20,0))

	win.columnconfigure(1,weight = 2)
	win.columnconfigure(0,weight = 2)
	win.columnconfigure(2,weight = 2)
	



    def _reproTrace(self):
	#try:

	#fetching the arguments entered by user
	self.arguments = (str(self.argumentsEntry.get())).split(" ")
	
	#if (numberOfRuns == 0):
	#	reprozipCmd = ['reprozip','trace']
	#else:
	reprozipCmd = ['reprozip','trace', '--continue']					
	reprozipCmd.append(str(self.tempPath.get()))
				
	#concatnating the reprozip trace command with user arguments
	self.arguments = reprozipCmd + self.arguments
	self.run_in_system_terminal(self.arguments)
	global flag
	flag = 0	
		
	with open(self.master.filepath) as fr:
		self.master.data = yaml.safe_load(fr)  
	
	self.numberOfRuns = len(self.master.data['runs'])
	print(self.numberOfRuns)
		
	self.master.data['runs'][self.numberOfRuns-1]['id'] = self.runName.get()
		    	
	#with open(self.master.filepath, "w") as fw:
	 #       yaml.safe_dump(data, fw)
		
			
	self.master.switch_frame(AddRunWindow)
	#except:
		#messagebox.showerror("Error", "Oops! Something went wrong! \nPlease Try Again!") 
        
        
class AddRunWindow(tk.Frame):
    
    def __init__(self, master):
        tk.Frame.__init__(self, master)
    	

	self.numberOfRuns = len(self.master.data['runs'])

        # Button for adding a new run 
        addRunButton = tk.Button(self, text = "Add Run", command= self._addRun, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "10")
        addRunButton.grid(row = 1, column =2, padx= (80,0))
       
        # Button to edit configuration window 
        nextButton = tk.Button(self, text=" Next ", command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "10")
        nextButton.grid(row = 3, column =2 ,padx= (80,0))
        
        # Label for naming runs
        runLabel = tk. Label(self, text = "Existing Runs",  font = "Helvetica 14")
        runLabel.grid(row = 0, column =0, sticky= "nw", pady = (10,5), padx = (40,0))
        
        # to read the runs from yaml file
        #with open(self.master.filepath) as fr:
         #   data = yaml.safe_load(fr)  
                  
        
        # Listbox to display existing runs
        runsList = tk.Listbox(self, bg = "white", fg= "black", width=23, height=12,font = "Helvetica 14")
        # Output the read run id to the GUI 
        for i in range(0, self.numberOfRuns):
            runsList.insert(tk.END, self.master.data['runs'][i]['id'])
         
        runsList.grid(row = 1, rowspan =3, columnspan = 2, sticky= "nw", padx = (40,0))

    def _addRun(self):
        self.numberOfRuns = self.numberOfRuns + 1 
        global flag
        flag = 1
        self.master.switch_frame(TraceWindow)
       
        
        
        
class editConfigurationWindow(tk.Frame):
      
    def __init__(self, master):
        tk.Frame.__init__(self, master)  
        
	#reading config file 

        #self.image = tk.PhotoImage(file = "back.png")
        # button to go back to Add Run Window
        backButton = tk.Button(self, text = "Back",  command = self._back, height ="2", width = "6")
        backButton.grid(row =0, column = 0, sticky = "nw", padx = (40,0))
        
        # button to Rename input/output files
        renameButton = tk.Button(self, text= "Rename I/O Files", command = self._renameFilesWindow , highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "13")
        renameButton.grid(row =2, column = 0, padx = (40,0))
        
        # button to switch to add/remove files window
        addFilesButton = tk.Button(self, text = "Add/Remove Files",  command = lambda: master.switch_frame(AddFilesWindow) , highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "13")
        addFilesButton.grid(row =2, column =3, padx = (40,0))
        
        # button to go back to Add Run Wind
        proceedButton = tk.Button(self, text = "Proceed",  command = lambda : master.switch_frame(PackWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "14")
        proceedButton.grid(row =3, column = 2, pady = (60,0), padx = (40,0))
        
        # Label for showing Trace Successfull
        traceSuccessfulLabel = tk.Label(self, text = "Trace Successfull !",font = "Helvetica 17", fg = "white" )
        traceSuccessfulLabel.grid(row =1, column = 0, columnspan = 4 ,pady= (30, 80), padx = (40,0), sticky = "nsew")
        
        
    def _back(self):
        global flag
        flag = 3
        self.master.switch_frame(AddRunWindow)
	
    def _renameFilesWindow(self):
	if (self.master.data['inputs_outputs']) :
		self.master.switch_frame(renameFilesWindow)
	else:
		messagebox.showerror("Error", "No Input/Output Files traced running the experiment!") 	
	
     
        
        
class renameFilesWindow(tk.Frame):
 
    def __init__(self, master):
        tk.Frame.__init__(self, master)  
	
	#reading config file 
	#with open(self.master.filepath) as fr:
         #   self.data = yaml.safe_load(fr) 
        
        #Label for input/output files 
        ioFilesLabel = tk.Label(self, text = "Input/Output Files", fg="white", font = "Helvetica 14")
        ioFilesLabel.grid(row= 0, column =0, sticky ="nw")
        
        # Label for Rename As
        renameLabel = tk.Label(self, text = "Rename As", fg="white", font = "Helvetica 14")
        renameLabel.grid(row = 1, column = 2, rowspan=2,  sticky ="nw", padx=(50,0))
        
        # Button to rename the file
        confirmButton = tk.Button(self, text = "Confirm",command = self._rename, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        confirmButton.grid(row = 4, column = 2,padx=(50,0) )
        
        # Button to Proceed
        proceedButton = tk.Button(self, text = "Back",command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        proceedButton.grid(row = 8, column = 2, padx=(50,0))
        
        self.index = tk.StringVar(self,value= " ")
        self.varEntry= tk.StringVar(self,value= "Select file from list")
        # entry for changing file name
        self.fileNameEntry = tk.Entry(self, textvariable = self.varEntry, bg = "white", width= "19", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
        self.fileNameEntry.grid(row = 2, column = 2, padx=(50,0))
    
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
        if(w.curselection()):
            self.index = int(w.curselection()[0])
            self.varEntry.set(self.master.data['inputs_outputs'][self.index]['name'])
            self.fileNameEntry.focus_set()
            
    def _writeList(self):
        # looping through the config file for input and output
        for i in range(0, len(self.master.data['inputs_outputs'])):
            prefix = ""
            if self.master.data['inputs_outputs'][i]['read_by_runs']:
                prefix += "[I]"
            
            if self.master.data['inputs_outputs'][i]['written_by_runs']:
                prefix += "[O]"
            
            prefix += " "
            prefix += self.master.data['inputs_outputs'][i]['name'] 
            self.iofilesListbox.insert(tk.END, prefix)
            
    def _rename(self):

	self.master.data['inputs_outputs'][self.index]['name'] = self.fileNameEntry.get()
        #with open(self.master.filepath, "w") as fw:
           # yaml.safe_dump(self.data, fw)
	
	updatedName = self.iofilesListbox.get(self.index)
	updatedName = updatedName[:updatedName.find(" ")]	
	updatedName = updatedName + " " + self.fileNameEntry.get()
	self.iofilesListbox.delete(self.index)
	self.iofilesListbox.insert(self.index, updatedName) 
        #self.iofilesListbox.delete(0,tk.END)
	#self._writeList()
        
        
class AddFilesWindow(tk.Frame):
    
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        
        #self.filepath = "config.yml"
	self.filepath = ".reprozip-trace/config.yml"
        
        AddRemoveLabel = tk.Label(self, text = "Add/Remove Files",  font = "Helvetica 14")
        AddRemoveLabel.grid(row = 0, sticky= "nsew", padx=(100,0))
        
        backButton = tk.Button(self, text = "Back",command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        backButton.grid(row = 3, sticky= "n", pady=(20,0), padx=(100,0))
        
        t = CheckboxTreeview(self, show="tree")
        t.grid(row = 1, sticky= "nsew", pady=(10,0), padx=(100,0))



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
        elif (self.data["inputs_outputs"]!= None) :
	    if any(i['path'] == p for i in self.data["inputs_outputs"]):
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
                    self.data["additional_patterns"].append(pathToAdd[0])

                
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
                
        Namelabel = tk.Label(self, text = "Name the RPZ Package as",  font = "Helvetica 14")
        Namelabel.grid(row =0, sticky="nsew", padx=(120,0))
        
        SaveAsbutton = tk.Button(self, text = "Pack",command = self.packRpz, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10") 
        SaveAsbutton.grid(row =2, padx=(120,0))
        
        self.rpzFileNameEntry = tk.Entry(self, textvariable = self.rpzFileName, width= "25", fg = "white",  font = "Helvetica 13 italic", insertbackground = "black")
        self.rpzFileNameEntry.grid(row =1, sticky="nsew", padx=(110,0), pady= (10,20))
        

  
    def packRpz(self):
        
        try:
	    
	    with open(self.master.filepath, "w") as fw:
           	yaml.safe_dump(self.master.data, fw)

	    self.fileToPack= (str(self.rpzFileNameEntry.get())).split()	
	    reprozipCmd = ['reprozip','pack']
	  
	
	#concatnating the reprozip pack command with user arguments
	    self.fileToPack = reprozipCmd + self.fileToPack
	    subprocess.check_call(self.fileToPack)
            fileName = self.rpzFileName.get()
            size = os.stat(fileName).st_size
            size = self.convert_bytes(size)
            successlabel = tk.Label(self, text = "Successfully Packed!",  font = "Helvetica 17")
            successlabel.grid(row =3, pady=(50, 0), padx=(120,0))
            
            fileSize = tk.StringVar(self, value= "Package size: "+size)
            
            displayName = tk.Label(self, textvariable = self.rpzFileName,  font = "Helvetica 15")
            displayName.grid(row =4, pady=(30, 0), padx=(120,0))
            displaySize = tk.Label(self, textvariable = fileSize,  font = "Helvetica 15")
            displaySize.grid(row =5, padx=(120,0)) 

	except:
    	    if os.path.isfile(self.rpzFileName.get()):
		messagebox.showerror("Error", "Target File Exists! \nPlease enter a new File Name") 
	    else:
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
