# Singularity unpacker for reprozip 
import subprocess
import os
import sys
import re
from shutil import copyfile
import yaml

#TODO:
# 1. Logging error for every bash command
# 2. Using existing reprozip utility functions for common tasks like copying busy box
# 3. Comments
# 4. integrating with exisitng unpacking coding design
# 5. Improving code structure

def extract_reprozip_file(filename):
    bashCommand = " tar -xf {}".format(filename)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    data_file="DATA.tar.gz"
    if data_file:
        bashCommand = " tar -xf {}".format(data_file)
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

args = sys.argv[1:]
filename, IMAGE_DIR = args

if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)
os.chdir(IMAGE_DIR)
filename = "../"+filename
extract_reprozip_file(filename)

SINGULARITY_DIR = "DATA/.singularity.d" 
run_env_file="90-environment.sh"
apps_file="95-apps.sh"
base_file="99-base.sh"
ENV_DIR = SINGULARITY_DIR+"/env"
SHELL_DIR = "DATA/bin"

def make_singularity_directories():
    if os.path.exists("DATA"):
        root_path = 'DATA'
        folders = ['proc','dev','sys']
        for folder in folders:
            os.mkdir(os.path.join(root_path,folder))
        folders = ['actions','libs','env']
        os.mkdir(SINGULARITY_DIR)
        for folder in folders:
            os.mkdir(os.path.join(SINGULARITY_DIR,folder)) 
        singularoty_files = ["labels.json","runscript","startscript"]
        for file in singularoty_files:
            open(os.path.join(SINGULARITY_DIR,file), 'a').close()

make_singularity_directories()

def copy_action_files():
    for file in os.listdir("../../singularitd_files/actions/"):
        bashCommand = "cp ../../singularitd_files/actions/{} DATA/.singularity.d/actions/".format(file)
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

copy_action_files()

def write_env_file(env,env_file):
    env_file = os.path.join(ENV_DIR, env_file)
    with open(env_file, 'w+') as f:
        for key,value in env.items():
            f.write(key+"='"+value+"'\n")
    bashCommand = "chmod +x {}".format(env_file)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

def make_environment_file():
    env_files = [run_env_file,apps_file,base_file]
    for file in env_files:
        open(os.path.join(ENV_DIR,file), 'a').close()
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
        print(len(runs))
        write_env_file(runs[0].get('environ'),run_env_file)

make_environment_file()

def make_runscript():
    source_config="METADATA/config.yml"
    my_dict = yaml.load(open(source_config))
    runs = my_dict['runs']
    cmd="#!/bin/sh \n"
    for run in runs:
        binary = run['binary']
        workingdir = run ['workingdir']
        run_file = run['argv'][1]
        if len(runs)>1:
            cmd += "source /.singularity.d/env/{}_env.sh \n".format(run['id'])
        cmd +="cd {0}\nexec {1} {2}\n".format(workingdir,binary,run_file)
    with open(os.path.join(SINGULARITY_DIR, "runscript"), 'w') as f:
        f.write(cmd)
    bashCommand = "chmod +x {}/runscript".format(SINGULARITY_DIR)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate() 

make_runscript()


def copy_busybox():
    if not os.path.exists(SHELL_DIR):
    	os.makedirs(SHELL_DIR)
    if not os.path.isfile(os.path.join(SHELL_DIR,"sh")):
	print("no sh in bin")
	bashCommand = "cp  ../bin/sh {}".format(SHELL_DIR)
	process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    	output, error = process.communicate()


copy_busybox()

def run_singularity_image():
    home = os.environ['HOME']
    print(home)
    bashCommand = "singularity run -C -H {}:/something  DATA".format(home)
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(output)

run_singularity_image()
