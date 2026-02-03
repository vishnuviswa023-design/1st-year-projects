principal = int(input("enter the amount:"))



while principal <= 0:
    print("Do not enter 0 or negative values")
    principal = int(input("Enter the amount: "))
    
rate =int(input("enter the rate"))
while rate <= 0:
    print("Do not enter 0 or negative values")
    rate = int(input("Enter the interest rate: "))
    
time = int(input("enter the time"))
while time <= 0:
    print("Do not enter 0 or negative values")
    time = int(input("Enter the year: "))

total=principal* pow((1+rate/100),time)

print(f"the amount {principal} for time {time} is rs {total:.2f}")
