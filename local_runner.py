from pydoc import doc
import sys
from app.f5_mig import *


def runner(file_name, c):
    print("Running migration script on: " + file_name)
    fun_f5_mig(file_name, 'local_' + str(c), 0)


counter = 0
if len(sys.argv) > 1:
    for file_name in sys.argv[1:]:
        runner(file_name, counter)
        counter += 1
else:
    while True:
        file_name = input(
            "Please provide config file/s or press Enter to stop\n").replace('"', '')
        if len(file_name) > 0:
            runner(file_name, counter)
            counter += 1
        else:
            break
