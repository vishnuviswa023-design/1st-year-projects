import random

print("\n Welcome to the dice roller game ")
print("------------------------------------")

total = 0
is_running = True

while is_running:
    dices = int(input("\n Enter how many dices you need max (1 or 2): "))
    
    if dices == 1:
        print("\n-----  Single Dice Roll -----")
        choice = input("Enter your choice (yes or no): ").lower()
        
        dice1 = random.randint(1, 6)
        print(f"\nYour dice 1 result = {dice1}")
        total = dice1

        if total > 4:
            print(f"Result: WOW! {total} is a top score")
        else:
            print(f"Result: {total} is low, try again")

        print("------------------------------")

    elif dices == 2:
        print("\n----- Double Dice Roll -----")
        choice = input("Enter your choice (yes or no): ").lower()
        
        dice2 = random.randint(1, 6)
        dice3 = random.randint(1, 6)
        print(f"\nDice 1 = {dice2}")
        print(f"Dice 2 = {dice3}")
        
        total = dice2 + dice3
        print(f"Total = {total}")

        if total > 10:
            print(f"Result: OMG! {total} is a top score")
        else:
            print(f"Result: {total} is low, try again")

        print("------------------------------")

    else:
        print("Please enter a valid message")

    if choice == "no":
        print("\nThank you for playing")
        is_running = False