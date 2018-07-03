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



def write_env_file(env,env_file):
    env_file = os.path.join(ENV_DIR, env_file)
    with open(env_file, 'w+') as f:
        for key,value in env.items():
            f.write(key+"='"+value+"'\n")
    bashCommand = "chmod +x {}".format(env_file)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()


def make_environment_file():
    #Write the environment file from config.yml file
    source_config="METADATA/config.yml"
    my_dict = yaml.load(open(source_config))
    runs = my_dict.get('runs')
    if len(runs) > 1:
        # create one env file for each run:
        for run in runs:
            filename = run['id']+"_env.sh"
            write_env_file(run.get('environ'), filename)
    else:
        write_env_file(runs[0].get('environ'),RUN_ENV_FILE)


def make_runscript():
    source_config="METADATA/config.yml"
    my_dict = yaml.load(open(source_config))
    runs = my_dict['runs']
    cmd = ''
    for run in runs:
        binary = run['binary']
        workingdir = run ['workingdir']
        run_file = run['argv'][1]
        if len(runs)>1:
            cmd += "source /.singularity.d/env/{}_env.sh \n".format(run['id'])
        cmd +="cd {0}\n{1} {2}\n".format(workingdir,binary,run_file)
    with open(os.path.join(SINGULARITY_DIR, "runscript"), 'w') as f:
        f.write(cmd)
    bashCommand = "chmod +x {}/runscript".format(SINGULARITY_DIR)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()


# Check if bin is present in the tar if not add bin and sh
def copy_busybox(tar):
    if not "bin" in tar.getnames():
        print("bin is absent")
        tar.add("../../bin",arcname="bin")
    elif not "sh" in tar.getnames():
        print("bin but no sh")
        tar.add("../../bin/sh", arcname='bin/sh')


def setup_singularity_image(filename):
	rpz = tarfile.open(filename, 'r:*')

	# Open the inner tar in the original, without extracting it to disk
	data = rpz.extractfile('DATA.tar.gz')
	tar = tarfile.open('DATA.tar.gz', fileobj=data)

	# Open the new tar we're writing
	new = tarfile.open('new.tar.gz', 'w:gz')
	recursive = True
	# For each member of the data tar
	for info in tar.getmembers():
	    # Make a new TarInfo, removing the DATA/ prefix from the file name
	    new_info = copy.copy(info)
	    new_info.name = info.name[5:]

	    if new_info.name:
	        # Copy the file from the inner tar to the new tar
	        if new_info.isreg():
	        	new.addfile(new_info, tar.extractfile(info.name))
	        	# with tarfile.open(info.name, "rb") as f:
	        	#     new.addfile(new_info, f)

	        elif new_info.isdir():
	        	new.addfile(new_info)
	        	# if recursive:
	        	#     for f in os.listdir(tar.extractfile(info.name)):
	        	#     	new.add(os.path.join(info.name, f), os.path.join('', f),recursive)
	        else:
	        	new.addfile(new_info)
	# Add the missing folders - proc,run, sys and temp_home
	folders = ['proc','dev','sys','temp_home']
	for folder in folders:
    	new.add("../../missing_folders/"+folder,folder)


    rpz.extractall()
    make_environment_file()
	make_runscript()
	copy_busybox(new)
    new.add(SINGULARITY_DIR,arcname=".singularity.d")
	tar.close()
	data.close()
	rpz.close()
	new.close()



def create_overlay_image(OVERLAY_IMAGE):
    bashCommand = "singularity image.create {}".format(OVERLAY_IMAGE)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(output)
    return error


def run_singularity_image(IMAGE_TAR_FILE):
    home = os.environ['HOME']
    if not create_overlay_image(OVERLAY_IMAGE):
        bashCommand = "singularity run  --overlay {0} -C -H {1}:/temp_home {2}".format(OVERLAY_IMAGE,home,IMAGE_TAR_FILE)
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        #copy the output from the overlay to some dir and destroy the overlay later
        print(output)




args = sys.argv[1:]
filename, IMAGE_DIR = args

if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)
os.chdir(IMAGE_DIR)
filename = "../"+filename
setup_singularity_image(filename)
run_singularity_image(IMAGE_TAR_FILE)


