import copy
import tarfile
import os
import sys
import yaml
import subprocess

# Open outer tar, the RPZ file
SINGULARITY_DIR = "../../.singularity.d"
RUN_ENV_FILE="90-environment.sh"
ENV_DIR = SINGULARITY_DIR+"/env"
OVERLAY_IMAGE = "repro_overlay.img"
IMAGE_TAR_FILE = "new.tar.gz"
MOUNT_DIR = "/mnt/"
source_config="METADATA/config.yml"
APP_DIR = "../../app_structure/sample_app"
SCIF_DIR = "../../app_structure/scif"
APP_ENV_DIR = APP_DIR+"/scif/env"


def write_env_file(env,env_file,apps=False):
    if apps:
        env_file = os.path.join(APP_ENV_DIR, env_file)
    else:
        env_file = os.path.join(ENV_DIR, env_file)
    with open(env_file, 'w+') as f:
        for key,value in env.items():
            f.write(key+"='"+value+"'\n")
    bashCommand = "chmod +x {}".format(env_file)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

  

def make_runscript(workingdir, binary, run_file, apps=False):
    cmd = "cd {0}\n{1} {2}".format(workingdir, binary, run_file)
    run_cmd = "run()\n{\n echo \"Nothing to run. Run Apps!!\"\n}\n\n"
    if apps:
        with open(os.path.join(APP_DIR+"/scif","runscript"), 'w') as f:
            f.write(cmd)
    else:
        run_cmd = "run()\n"
        run_cmd += "{\n\t" + cmd + "\n}\n"
    upload_download_cmd = "upload()\n{\n"
    upload_download_cmd += "\tcp " + MOUNT_DIR + "\"$1\" " + workingdir + "\n}\n\n"
    upload_download_cmd += "download()\n{\n"
    upload_download_cmd += "\tcp {0}/".format(workingdir) + "\"$1\" " + MOUNT_DIR + "\n}\n\n"
    upload_download_cmd += "if [ \"$#\" -gt 0 ]\nthen \n \tcase \"$1\" in \n\t\t\"upload\"|\"download\")\n\t\t\t\"$1\" \"$2\" \n\t\t;;\n\t\t*)\n\t\techo \"Invalid arguments!!\" >&2\n\t\texit 1\n\t\t;;\n\tesac\nelse\n\trun\nfi"
    with open(os.path.join(SINGULARITY_DIR, "runscript"), 'w') as f:
	f.write(run_cmd)
        f.write(upload_download_cmd)

def make_main_app_base_script(app_name):
    print("rached 94")
    cmd =  "SCIF_APPDATA_{0}=/scif/data/{1}\n".format(app_name,app_name)
    cmd += "SCIF_APPMETA_{0}=/scif/apps/{1}/scif\n".format(app_name,app_name)
    cmd += "SCIF_APPROOT_{0}=/scif/apps/{1}\n".format(app_name,app_name)
    cmd += "SCIF_APPBIN_{0}=/scif/apps/{1}/bin\n".format(app_name,app_name)
    cmd += "SCIF_APPLIB_{0}=/scif/apps/{1}/lib\n".format(app_name,app_name)
    cmd += "export SCIF_APPDATA_{0} SCIF_APPROOT_{1} SCIF_APPMETA_{2} SCIF_APPBIN_{3} SCIF_APPLIB_{4}\n".format(app_name,app_name,app_name,app_name,app_name)
    cmd += "SCIF_APPENV_{0}=/scif/apps/{1}/scif/env/90-environment.sh\n".format(app_name,app_name)
    cmd += "export SCIF_APPENV_{0}\n".format(app_name)
    cmd += "SCIF_APPLABELS_{0}=/scif/apps/{1}/scif/labels.json\n".format(app_name,app_name)
    cmd += "export SCIF_APPLABELS_{0}\n".format(app_name)
    cmd += "SCIF_APPRUN_{0}=/scif/apps/{1}/scif/runscript\n".format(app_name,app_name)
    cmd += "export SCIF_APPRUN_{0}\n".format(app_name)
    with open(os.path.join(ENV_DIR, "94-appsbase.sh"), 'a') as f:
        f.write(cmd)


def make_app_specific_base_script(app_name):
    cmd = "SCIF_APPNAME={}\n".format(app_name)
    cmd += "SCIF_APPROOT=\"/scif/apps/{}\"\n".format(app_name)
    cmd += "SCIF_APPMETA=\"/scif/apps/{}/scif\"\n".format(app_name)
    cmd += "SCIF_DATA=\"/scif/data\"\n"
    cmd += "SCIF_APPDATA=\"/scif/data/{}\"\n".format(app_name)
    cmd += "SCIF_APPINPUT=\"/scif/data/{}/input\"\n".format(app_name)
    cmd += "SCIF_APPOUTPUT=\"/scif/data/{}/output\"\n".format(app_name)
    cmd += "export SCIF_APPDATA SCIF_APPNAME SCIF_APPROOT SCIF_APPMETA SCIF_APPINPUT SCIF_APPOUTPUT SCIF_DATA\n"
    with open(os.path.join(APP_ENV_DIR, "01-base.sh"), 'w') as f:
        f.write(cmd)

# Check if bin is present in the tar if not add bin and sh
def copy_busybox(tar):
    if not "bin" in tar.getnames():
        print("bin is absent")
        tar.add("../../bin",arcname="bin")
    elif not "sh" in tar.getnames():
        print("bin but no sh")
        tar.add("../../bin/sh", arcname='bin/sh')


def deleteContent(fName):
    with open(fName, "w"):
        pass

def add_singularity_folder(tar):
    # check if the runs are multiple or single
    my_dict = yaml.load(open(source_config))
    runs = my_dict['runs']
    copy_busybox(tar)
    deleteContent(os.path.join(ENV_DIR, "94-appsbase.sh"))
    if len(runs) > 1:
	print("multiple runs")
        # App structure is present
        # First add the SCIF folder 
        tar.add(SCIF_DIR, arcname="scif")
        for run in runs:
            binary = run['binary']
            workingdir = run['workingdir']
            run_file = run['argv'][1]
            app_name = run['id']
            make_runscript(workingdir, binary, run_file, apps=True)
            write_env_file(runs[0].get('environ'), RUN_ENV_FILE, apps=True)
            make_app_specific_base_script(app_name)
            make_main_app_base_script(app_name)
            # add the modified app.
            tar.add(APP_DIR, arcname="scif/apps/" + app_name)

    else:
        write_env_file(runs[0].get('environ'),RUN_ENV_FILE)
        make_runscript(runs[0]['workingdir'], runs[0]['binary'], runs[0]['argv'][1])
    tar.add(SINGULARITY_DIR, arcname=".singularity.d")
    


def setup(filename):
    rpz = tarfile.open(filename, 'r:*')

    # Open the inner tar in the original, without extracting it to disk
    data = rpz.extractfile('DATA.tar.gz')
    tar = tarfile.open('DATA.tar.gz', fileobj=data)

    # Open the new tar we're writing
    new = tarfile.open('new.tar.gz', 'w:gz')
    # For each member of the data tar
    for info in tar.getmembers():
        # Make a new TarInfo, removing the DATA/ prefix from the file name
        new_info = copy.copy(info)
        new_info.name = info.name[5:]
        if new_info.name:
            # Copy the file from the inner tar to the new tar
            if new_info.isreg():
                new.addfile(new_info, tar.extractfile(info.name))
            elif new_info.isdir():
                new.addfile(new_info)
            else:
                new.addfile(new_info)
    # Add the missing folders - proc,run, sys and temp_home
    folders = ['proc','dev','sys','temp_home','mnt']
    for folder in folders:
        new.add("../../missing_folders/"+folder,folder)
    print("added missing folder")

    rpz.extractall()
    add_singularity_folder(new)
    print("added singularioty folder")
    tar.close()
    data.close()
    rpz.close()
    new.close()



def create_overlay_image(OVERLAY_IMAGE):
    if not os.path.exists(OVERLAY_IMAGE):
    	bashCommand = "singularity image.create {}".format(OVERLAY_IMAGE)
    	process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    	output, error = process.communicate()
    	print(output)
    	return error
    return 0



def run(IMAGE_TAR_FILE,app):
    home = os.environ['HOME']
    if not create_overlay_image(OVERLAY_IMAGE):
        if app:
            print("running app:{}!".format(app))
            bashCommand = "singularity run  --overlay {0} --app {1} -C -H {2}:/temp_home {3}".format(OVERLAY_IMAGE,app,home,IMAGE_TAR_FILE)
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
	else:
	    # get the name of all the apps
            my_dict = yaml.load(open(source_config))
            runs = my_dict['runs']
            for run in runs:	
		app = run['id']    
            	print("running app:{}!".format(app))
            	bashCommand = "singularity run  --overlay {0} --app {1} -C -H {2}:/temp_home {3}".format(OVERLAY_IMAGE,app,home,IMAGE_TAR_FILE)
            	process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            	output, error = process.communicate()

def download(IMAGE_TAR_FILE,filename):
    home = os.environ['HOME']
    current_dir = os.getcwd()
    bashCommand = "singularity run  -B {0}:{1} --overlay {2} -C -H {3}:/temp_home {4} download {5}".format(current_dir,MOUNT_DIR,OVERLAY_IMAGE, home, IMAGE_TAR_FILE, filename)
    print(bashCommand)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()


def upload(IMAGE_TAR_FILE, filename):
    home = os.environ['HOME']
    current_dir = os.getcwd()
    bashCommand = "singularity run  -B {0}:{1} --overlay {2} -C -H {3}:/temp_home {4} upload {5}".format(current_dir,MOUNT_DIR,OVERLAY_IMAGE, home, IMAGE_TAR_FILE, filename)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()


args = sys.argv[1:]
cmd = args[0]
print(cmd)
if cmd=="setup":
    rpz_file, IMAGE_DIR = args[1:]
    if not os.path.exists(IMAGE_DIR):
        os.makedirs(IMAGE_DIR)
    os.chdir(IMAGE_DIR)
    rpz_file = "../" + rpz_file
    setup(rpz_file)
elif cmd=="run":
    IMAGE_DIR = args[1]
    app = args[2] 
    os.chdir(IMAGE_DIR)
    print(app)
    run(IMAGE_TAR_FILE,app)
elif cmd in ["upload","download"]:
    IMAGE_DIR,filename = args[1:]
    os.chdir(IMAGE_DIR)
    print(IMAGE_DIR)
    if not filename:
        print("output file missing!")
    globals()[cmd](IMAGE_TAR_FILE,filename)


