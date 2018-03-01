#!/usr/local/bin/python3
import sys
import os
import os.path as path
import subprocess as sp

def main():
	BASE = "/home/torut235/linuxpintos/"
	prog = None
	if len(sys.argv) > 1:
		prog = sys.argv[1]


	print("Compiling threads...")
	out, errs, retcode = gmake(path.join(BASE, "src/threads"))
	if errs:
		print(errs, end="")
	if retcode != 0:
		return -1

	print("Compiling userprog...")
	out, errs, retcode = gmake(path.join(BASE, "src/userprog"))
	if errs:
		print(errs, end="")
	if retcode != 0:
		return -1

	os.chdir(path.join(BASE, "src/userprog/build"))

	if prog and path.isfile(path.join(BASE, "src/examples", "{}.c".format(prog))):
		print("Compiling examples...")
		out, errs, retcode = gmake(path.join(BASE, "src/examples"))
		if errs:
			print(errs, end="")
		if retcode != 0:
			return -1
		xfer = True

		os.chdir(path.join(BASE, "src/userprog/build"))

		if xfer:
			print("Transferring program...")
			cmd = "pintos --qemu -- -q rm {}".format(prog)
			try:
				proc = sp.Popen(cmd.split(" "))
				proc.wait()
			except KeyboardInterrupt:
				pass

			cmd = "pintos --qemu -p {0} -a {1} -- -q".format(path.join(BASE, "src/examples", prog), prog)
			print(cmd)
			proc = sp.Popen(cmd.split(" "))
			proc.wait()

	print("fardigt")
	return 0
"""
	if prog:
		cmd = "pintos --qemu -- run"
	else:
		cmd = "pintos --qemu --"

	print(cmd, "\n")
	try:
		if prog:
			pass#proc = sp.Popen(cmd.split(" ") + ["'{} {}'".format(prog, args)])
		else:
			pass#proc = sp.Popen(cmd.split(" "))
		#proc.wait()
	except KeyboardInterrupt:
		pass
"""

def gmake(_dir):
	os.chdir(_dir)
	proc = sp.Popen("make", stdout=sp.PIPE, stderr=sp.PIPE)
	out, errs = proc.communicate()
	proc.wait()
	return (out.decode(), errs.decode(), proc.returncode)

if __name__ == "__main__":
	sys.exit(main())
