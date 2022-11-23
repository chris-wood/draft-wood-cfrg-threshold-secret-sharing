import sys
import json

vector_keys = [
    "k",
    "secret",
    "randomness",
    "shares",
    "shared_secret",
]

def wrap_print(arg, *args):
    line_length = 69
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)

def format_vector(vector):
    for key in vector_keys:
        for vector_key in vector:
            if key == vector_key:
                if type(vector[key]) == type([]):
                    wrap_print(key + ":", ",".join(vector[key]))
                else:
                    wrap_print(key + ":", vector[key])

for fname in sys.argv[1:]:
    with open(fname, "r") as fh:
        vector = json.loads(fh.read())
        name = vector["name"]
        print("")
        print("## " + name + "\n")
        print("~~~")
        format_vector(vector)
        print("~~~")
