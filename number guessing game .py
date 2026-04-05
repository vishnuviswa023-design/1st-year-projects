import random

max=100
low=1

answer=random.randint(low, max)
keep_going=True
guess=0
print(f"guess the number between {low} and {max}")

while keep_going:
    guesses=input("enter your guess")
    if guesses.isdigit():
        guesses=int(guesses)
        guess+=1
        if guesses < low or guesses > max:
            print("its out of range ")       
        elif guesses < answer:
            print("its too low bro")  
        elif guesses > answer:
            print("its too high bro")
        elif guesses==answer:
            print("congrats bro")   
            print(f"your guesses were {guess}")
            keep_going=False
            
    else:
        print("invalid answer")
        print(f"guess the number between {low} and {max}")
        
    