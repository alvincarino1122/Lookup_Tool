#Master script

# my_script.py
from ip import ip_function
from domain import domain_function


def main():
    while True:
        choice = input("\nDo you want to check an (i)p or a (d)omain? (type 'exit' to quit): ").strip().lower()
        
        if choice == "i":
            ip_function()
        elif choice == "d":
            domain_function()
        elif choice == "exit":
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 'IP', 'domain', or 'exit'.")

if __name__ == "__main__":
    main()