import sys
from f5_mig import *

if len(sys.argv)>1:
	fun_f5_mig(sys.argv[1], 'local', 0)
else:
	fun_f5_mig(input("Please provide path to config files\n"), 'local', 0)
