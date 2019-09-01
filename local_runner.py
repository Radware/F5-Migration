import sys
from app.f5_mig import *

if len(sys.argv)>1:
	file_names=""
	for i in sys.argv[1:]:
		file_names=file_names+"$val$"+i
	fun_f5_mig(file_names[5:], 'local', 0)
else:
	fun_f5_mig(input("Please provide path to config files\n"), 'local', 0)
