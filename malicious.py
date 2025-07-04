import os
import pickle
import tarfile

def command_injection():
    user_input = input("Enter directory to list: ")
    # Vulnerable: user input is directly used in a shell command
    os.system(f"ls {user_input}")

def insecure_eval():
    user_code = input("Enter a Python expression to evaluate: ")
    # Vulnerable: eval executes arbitrary code
    result = eval(user_code)
    print("Result:", result)

def insecure_deserialization():
    data = input("Enter serialized data: ")
    # Vulnerable: loading untrusted data
    obj = pickle.loads(data.encode('latin1'))
    print("Deserialized object:", obj)

def directory_traversal():
    filename = input("Enter filename to read: ")
    # Vulnerable: no validation of file path
    with open(filename, 'r') as f:
        print(f.read())

def tarfile_path_traversal():
    tar_path = input("Enter tar file path: ")
    with tarfile.open(tar_path, 'r') as tar:
        # Vulnerable: may write files outside intended directory
        tar.extractall(path=".")

def main():
    print("1. Command Injection")
    print("2. Insecure eval()")
    print("3. Insecure Deserialization")
    print("4. Directory Traversal")
    print("5. Tarfile Path Traversal")
    choice = input("Choose a vulnerability demo (1-5): ")
    if choice == '1':
        command_injection()
    elif choice == '2':
        insecure_eval()
    elif choice == '3':
        insecure_deserialization()
    elif choice == '4':
        directory_traversal()
    elif choice == '5':
        tarfile_path_traversal()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
