import os
import subprocess
import pickle


def vulnerable_command(user_input):
    os.system('echo ' + user_input)


def vulnerable_eval(data):
    result = eval(data)
    return result


def vulnerable_pickle(serialized_data):
    obj = pickle.loads(serialized_data)
    return obj


def vulnerable_subprocess(cmd):
    subprocess.call(cmd, shell=True)


def safe_command(user_input):
    import shlex
    safe_arg = shlex.quote(user_input)
    os.system(f'echo {safe_arg}')
