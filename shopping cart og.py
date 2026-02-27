foods=[]
prices=[]
total=0

while True:
    food=input("enter the food items(q to quet)")
    if food .lower() =="q":
        break
    else:
        price=float(input(f" price for {food}"))
        foods.append(food)
        prices.append(price)
print("--------------your cart-------------")
for food in foods:
    print(food)
for price in prices:
    total+=price
print(f"your total is {total}$")
print("-----------------------------------------")
   