import os
import subprocess
import tkinter as tk
from tkinter import filedialog
import yaml

# Run 0 being the first run
numberOfRuns = 0
#to keep a check on which was the last window visited, -1 saying no widnows prior
flag = -1


class ReprozipApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self._frame = None
        self.switch_frame(TraceWindow)

    def switch_frame(self, frame_class):
        """Destroys current frame and replaces it with a new one."""
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()


class TraceWindow(tk.Frame):

    def __init__(self, master):
        
        self.tempPath = tk.StringVar()
        tk.Frame.__init__(self, master)

        # setting the parameter for the whole frame
        self.master.title("ReproZip")
        self.master.tk_setPalette(background= '#6E53BE')
        self.master.resizable(False,False)
        self.master.geometry("450x400")
        self.pack(fill=tk.BOTH, expand = 1)
        self.tempPath.set("Set working directory using Browse")
     
        default = tk.StringVar(self, value= "run " + str(numberOfRuns) )
        
        # Entry widget for entering the name
        self.master.runName = tk.Entry(self, textvariable = default, bg = "white", width= "19", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
        self.master.runName.focus_set()
        self.master.runName.place(x = 180, y = 60)
        
        # Asking for the Name of Run
        labelRunName = tk.Label(self, text = "Name of Run",  font = "Helvetica 14")
        labelRunName.place(x= 80, y = 60)
        
        # Textbox for Terminal using Text
        textTerminal = tk.Text(self, width = "40",height = "8", fg="black" )
        textTerminal.place(x= 80, y = 100)
        
        # Browse button
        browseButton = tk.Button(self, text="Browse",command = self._askopenfile, highlightbackground="#404040", highlightthickness="0",fg='white', height ="2", width = "8")
        browseButton.place(x=80,y=280)
       
        # Display file path
        workDir = tk.Label(self, textvariable =self.tempPath, fg="white", font = "Helvetica 11 italic", width ="40")
        workDir.place(x= 80, y = 230)
        
        # Trace button
        traceButton = tk.Button(self, text="Trace", command= self._reproTrace,highlightbackground="#404040", highlightthickness="0",fg='white', height ="2", width = "8")
        traceButton.place(x= 300, y = 280)
        
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
        
      # setting the parameter for the whole frame
        self.master.title("ReproZip")
        self.master.tk_setPalette(background= '#6E53BE')
        self.master.resizable(False,False)
        self.master.geometry("450x400")
        self.pack(fill=tk.BOTH, expand = 1)
    
        # Button for adding a new run 
        addRunButton = tk.Button(self, text = "Add another Run", command= self._addRun, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "15")
        addRunButton.place(x= 260, y = 105)
       
        # Button to edit configuration window 
        nextButton = tk.Button(self, text=" Next ", command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "15")
        nextButton.place(x = 260, y = 220)
        
        # Label for naming runs
        runLabel = tk. Label(self, text = "Existing Runs",  font = "Helvetica 14")
        runLabel.place(x = 85, y = 70 )
        
        # to read the runs from yaml file
        self.filepath = "./config.yml"
        
        with open(self.filepath) as fr:
            data = yaml.safe_load(fr)  
           
        if(flag != 3):
        #if data['runs'][numberOfRuns]['id'] == "run "+ str(numberOfRuns) :
            data['runs'][numberOfRuns]['id'] = self.master.runName.get()
            with open(self.filepath, "w") as fw:
                yaml.safe_dump(data, fw)

        # Listbox to display existing runs
        runsList = tk.Listbox(self, bg = "white", fg= "black", width=23, height=10,font = "Helvetica 14")
        # Output the read run id to the GUI 
        for i in range(0, numberOfRuns+1):
            runsList.insert(tk.END, data['runs'][i]['id'])
         
        runsList.place(x=45, y=95)
        
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
        
        # setting the parameter for the whole frame
        self.master.title("ReproZip")
        self.master.tk_setPalette(background= '#6E53BE')
        self.master.resizable(False,False)
        self.master.geometry("450x400")
        self.pack(fill=tk.BOTH, expand = 1)
        
        # button to go back to Add Run Window
        backButton = tk.Button(self, text = "Back",  command = self._back, highlightbackground="black", highlightthickness="0",fg='white', height ="2")
        backButton.place(x = 40, y = 10)
        
        # button to Rename input/output files
        renameButton = tk.Button(self, text= "Rename Input/Output Files", command = lambda : master.switch_frame(renameFilesWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "19")
        renameButton.place(x = 30, y = 200)
        
        # button to switch to add/remove files window
        addFilesButton = tk.Button(self, text = "Add/Remove Files",  command = self._back, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "19")
        addFilesButton.place(x = 245, y = 200)
        
        # button to go back to Add Run Window
        packButton = tk.Button(self, text = "Pack",  command = self._back, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width= "14")
        packButton.place(x = 163, y = 300)
        
        # Label for showing Trace Successfull
        traceSuccessfulLabel = tk.Label(self, text = "Trace Successfull !",font = "Helvetica 17", fg = "white" )
        traceSuccessfulLabel.place(x=150, y = 80)
        
    def _back(self):
        global flag
        flag = 3
        self.master.switch_frame(AddRunWindow)
     

class renameFilesWindow(tk.Frame):
 
    def __init__(self, master):
        tk.Frame.__init__(self, master)  
        
        # setting the parameter for the whole frame
        self.master.title("ReproZip")
        self.master.tk_setPalette(background= '#6E53BE')
        self.master.resizable(False,False)
        self.master.geometry("450x400")
        self.pack(fill=tk.BOTH, expand = 1)
        self.index = tk.StringVar(self,value= " ")
        self.varEntry= tk.StringVar(self,value= "Select file from list")
        
        #Label for input/output files 
        ioFilesLabel = tk.Label(self, text = "Input/Output Files", fg="white", font = "Helvetica 14")
        ioFilesLabel.place(x = 70, y = 50 )
        
        # Label for Rename As
        renameLabel = tk.Label(self, text = "Rename As", fg="white", font = "Helvetica 14")
        renameLabel.place(x = 260, y = 78 )
        
        # Button to rename the file
        confirmButton = tk.Button(self, text = "Confirm",command = self._rename, highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        confirmButton.place (x = 300, y = 150)
        
        # Button to Proceed
        proceedButton = tk.Button(self, text = "Back",command = lambda : master.switch_frame(editConfigurationWindow), highlightbackground="black", highlightthickness="0",fg='white', height ="2", width = "10")
        proceedButton.place (x = 300, y = 240)
        
        # entry for changing file name
        self.fileNameEntry = tk.Entry(self, textvariable = self.varEntry, bg = "white", width= "19", fg = "black",  font = "Helvetica 13 italic", insertbackground = "black")
        self.fileNameEntry.place(x = 260, y = 100)

        # to read the runs from yaml file
        self.filepath = "./config.yml"
        
        # Listbox to display the input and output files
        self.iofilesListbox = tk.Listbox(self, bg = "white", fg= "black", font = "Helvetica 15", width=21, height=13,)
        self.iofilesListbox.bind('<<ListboxSelect>>', self._onSelect)
        self.iofilesListbox.place(x=35, y=75)
        self._writeList()
        #self._writeList()
        #self._writeList()
        
        yscroll = tk.Scrollbar(command=self.iofilesListbox.yview, orient=tk.VERTICAL)
        yscroll.place(height = 233.5, x=226, y = 75.5 )
        self.iofilesListbox.configure(yscrollcommand=yscroll.set)
        
    def _onSelect(self,event):
        w = event.widget
        with open(self.filepath) as fr:
            data = yaml.safe_load(fr)   
        if(w.curselection()):
            self.index = int(w.curselection()[0])
            self.varEntry.set(data['inputs_outputs'][self.index]['name'])
            self.fileNameEntry.focus_set()
            
    def _writeList(self):
        with open(self.filepath) as fr:
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
        with open(self.filepath) as fr:
            data = yaml.safe_load(fr) 
     
        data['inputs_outputs'][self.index]['name'] = self.fileNameEntry.get()
        with open(self.filepath, "w") as fw:
            yaml.safe_dump(data, fw)
        
        self.iofilesListbox.delete(0,tk.END)
        self._writeList()
        

if __name__ == "__main__":
    app = ReprozipApp()
    app.mainloop()
