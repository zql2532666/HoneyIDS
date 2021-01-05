import pyminizip
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning) 

# pyminizip.compress("/srcfile/path.txt", "file_path_prefix", "/distfile/path.zip", "password", int(compress_level))
"""
Args:
1. src file path (string)
2. src file prefix path (string) or None (path to prepend to file)
3. dst file path (string)
4. password (string) or None (to create no-password zip)
5. compress_level(int) between 1 to 9, 1 (more fast) <---> 9 (more compress) or 0 (default)
"""

compression_level = 5 
pyminizip.compress("todo.txt", "malware-num", "malware-num.zip", "honeyid$", compression_level)


"""
dioena_malware_files
    >   honey_token
        >   malware_zipped files

On add node api end point, needs to write logic such that if the honeynode is of type, dionea, 
a new folder should be created under dioena_malware_files
"""