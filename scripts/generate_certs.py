#!/usr/bin/env python3

import sys
import os
import re
import subprocess

def extract_key(enc,typ,name,filename):
    if (enc != "string" and enc != "binary"):
        sys.exit(1)
    if (typ != "macro" and typ != "variable"):
        sys.exit(1)

    output = ""
    if (typ == "variable"):
        if (enc == "binary"):
            output = "const unsigned char " + name + "[] = {\n"
            data = subprocess.run(["xxd","-i",filename],capture_output=True).stdout.decode("utf-8")
            output += '   ' + '   '.join(data.splitlines(keepends=True)[1:-2])
            output += "};\n"
        elif (enc == "string"):
            output = "const char " + name + "[] =\n"
            with open(filename) as f:
                for line in f.read().splitlines():
                    output += "    \"" + line + "\\r\\n\"\n"
                output = output[:-1] + ";\n"
    elif (typ == "macro"):
        if (enc == "binary"):
            output = "#define " + name + " {\n"
            data = subprocess.run(["xxd","-i",filename],capture_output=True).stdout.decode("utf-8")
            output += '  ' + '  '.join(data.splitlines(keepends=True)[1:-2])
            output = "".join([(line + (77-len(line))*" " + "\\\n") for line in output.splitlines()])
            output += "}\n"
        elif (enc == "string"):
            output = "#define " + name + "\n"
            with open(filename) as f:
                for line in f.read().splitlines()[:-1]:
                    output += "    \"" + line + "\\r\\n\"\n"
                output = output[:-1] + "\n"
            output = "".join([(line + (75-len(line))*" " + "\\\n") for line in output.splitlines()])
            with open(filename) as f:
                output += "    \"" + f.read().splitlines()[-1] + "\\r\\n\"\n"
    return output

def run_main():
    if not os.path.exists("include/mbedtls"):
       print("Must be run from root")
       sys.exit(2)

    CERTS = "library/certs.c"
    CERTS_TMP = CERTS+".tmp"
    CERTS_NEW = CERTS+".new"

    with open(CERTS) as old_f, open(CERTS_TMP,"w") as new_f:
        line = old_f.readline()
        while line:
            if re.fullmatch("^/\*\s*BEGIN FILE.*\*/$\n",line):
                new_f.write(line)
                args = line.split(" ")[3:7]
                add = extract_key(args[0],args[1],args[2],args[3])
                new_f.write(add)
                while not re.fullmatch("^/\*\s*END FILE\s*\*/$\n",line):
                    line = old_f.readline()
            new_f.write(line)
            line = old_f.readline()

if __name__ == "__main__":
    run_main()
