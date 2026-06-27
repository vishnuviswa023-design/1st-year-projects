def balance(current_balance):
    print("-------------------------------")
    print(f"your current bank balance  is : {current_balance}")
    if current_balance < 0:
        print("your bank balance was in minus")
    elif current_balance == 0:
        print("your balance was 0")
    print("-------------------------------")

def deposit(amount):
    print("-------------------------------")
    print(f"your deposited amount is {amount}")
    if amount < 0:
        print("negative balance was insufficient amount")
    elif amount == 0:
        print("you deposited zero rupees")
    print("-------------------------------")

def withdrawl(withdrawl, balance):
    print("-------------------------------")		
    print(f"your withdrawl amount is:{withdrawl}")
    if withdrawl > balance:
        print("your balance is less than your withdrwal amount ")
    elif withdrawl == balance:
        print("are you sure to withdraw all amount from your bank")
    print("-------------------------------")

current_balance = 0

while True:
    print("\n=== BANK MENU ===")
    print("1. Check Balance")
    print("2. Deposit Money")
    print("3. Withdraw Money")
    print("4. Exit")
    
    choice = input("Enter your choice (1-4): ")
    if choice == "1":
        balance(current_balance)
    elif choice == "2":
        amount = float(input("enter amount to be deposited: "))
        deposit(amount)
        current_balance += amount
    elif choice == "3":
        amount = float(input("enter amount to be withdrawn: "))
        withdrawl(amount, current_balance)
        current_balance -= amount
    elif choice == "4":
        print("thank you for your arrival,have a nice day")
        break
    else:
        print("invalid choice,enter choice between(1-4)")