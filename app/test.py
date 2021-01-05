import os 
token = "xx"

dir_path = f"dioena_malware_files/{token}"

if os.path.exists(dir_path):
    # write the binary file 
    print("dir exists")
else:
    print("making dir path")
    os.mkdir(dir_path)

# check if the dir exists

# if not create the dir