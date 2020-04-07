
#! /usr/bin/python3

import subprocess
import sys
import os

# TODO. Check if all requirments are installed: qemu cu strace ,file, etc.

CORES_DIR = "tests/cores/"

lib_paths = {
        "arm32_dynamic_core"         : "/usr/arm-linux-gnueabihf/",
        "arm64_dynamic_core"         : "/usr/aarch64-linux-gnu/",
        "i386_dynamic_core"          : "/usr/lib32",
        "mips32_dynamic_LSB_core"    : "/usr/mipsel-linux-gnu",
        "mips32_dynamic_MSB_core"    : "/usr/mips-linux-gnu",
        "mips64_dynamic_LSB_core"    : "/usr/mips64el-linux-gnuabi64",
        "x86-64_dynamic_core"        : "/usr/lib64"
}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def get_ok():
        return bcolors.OKGREEN + "[PASSED]" + bcolors.ENDC

    @staticmethod
    def get_fail():
        return bcolors.FAIL + "[FAILED]" + bcolors.ENDC

    @staticmethod
    def new_test(name):
        return bcolors.OKBLUE + ("[TEST] Test for file %s" % (name)) + bcolors.ENDC

    @staticmethod
    def log(msg):
        string = ""
        if (msg[0] == True):
            string = bcolors.get_ok()
        else:
            string = bcolors.get_fail()

        print("%s %s" % (string, msg[1]))


def get_qemu_env(name):
    print(name)
    print(lib_paths.keys())
    if name in lib_paths.keys():
        return lib_paths[name]
    return ""

def run_file(path):
	proc = subprocess.Popen(["file", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	out = proc.communicate()[0]

	if proc.returncode != 0:
		return (False, "File did not return 0. Code: %d" % (proc.returncode))

	if b"ELF" not in out:
		return (False, "Invalid file output. Message: %s" % (out))

	return (True, out)

def run_readelf(path):
	proc = subprocess.Popen(["readelf", "-a", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	out = proc.communicate()[0]

	if proc.returncode != 0:
		return (False, "File did not return 0. Code: %d" % (proc.returncode))

	if b"ELF" not in out:
		return (False, "Invalid readelf output. Message: %s" % (out))

	if b"Warning" in out or b"Error" in out:
		return (False, "Found warnings/errors in readelf output. Message %s" (out))

	return (True, 'Readelf passed')


def run_program(path, core):
        menv = os.environ.copy()
        menv["QEMU_LD_PREFIX"] = get_qemu_env(os.path.basename(core))
        proc = subprocess.Popen([path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=menv)
        out = proc.communicate()[0]
        print(menv["QEMU_LD_PREFIX"])
        if proc.returncode != 42:
            return (False, "File did not return 42. Code: %d" % (proc.returncode))

        if b"Hello world" not in out:
            return (False, "Invalid program output. Message: %s" % (out))

        return (True, 'Running passed')

def run_reconstruction(core, result):
	proc = subprocess.Popen(["./core2elf", core, "-o", result], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
	proc.communicate()

	if os.path.exists(result) is False:
		return (False, "Could not reconstruct file")

	os.chmod(result, 0o777)
	return (True, "Reconstrution done.")

def run_test(path):
    opath = os.path.abspath("elf.out")
    try:
        r = run_reconstruction(path, opath)
        bcolors.log(r)
    except:
        bcolors.log((False, "Exception in reconstruction"))
    try:
        r = run_file(opath)
        bcolors.log(r)
    except:
        bcolors.log((False, "Exception in file"))
    try:
        r = run_readelf(opath)
        bcolors.log(r)
    except:
        bcolors.log((False, "Exception in readelf"))
    try:
        r = run_program(opath, core)
        bcolors.log(r)
    except Exception as e:
        print(e)
        bcolors.log((False, "Exception in run_program"))


#run_test("tests/cores/x86-64_static_core")
if __name__ == "__main__":
    cores_abs_path = os.path.abspath(CORES_DIR)
    cores = os.listdir(cores_abs_path)
    for core in cores:
        path = os.path.join(cores_abs_path, core)
        print(bcolors.new_test(core))
        run_test(path)
        print("")
