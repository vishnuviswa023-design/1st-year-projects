operators=(input("enter the symbols(+,-,*,/)"))
num1=float(input("enter your value"))
num2=float(input("enter your value"))

if operators=="+":
	ans=num1+num2
	print(f"your answer is {ans}")
	
elif operators=="-":
   ans=num1-num2
   print(f"your answer is {ans}")
   
elif operators=="*":
   ans=num1*num2
   print(f"your answer is {ans}")
   
elif operators=="/":
	ans=num1/num2
	print(f"your answer is {ans}")
	
else:
	print("you entered a invalid symbol")
	