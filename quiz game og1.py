questions=("which is the largest continent ","which animal lays biggest egg","which country does have more nuclear bombs","who is the prime minister of india")

options=(("A.America","B.asia","C.antartica","D.australia"),
("A.hen","B.peacock","C.ostrich","D.penguin"),
("A.china","B.America","C.Russia","D.India"),
("A.Nehru","B.subash chandra bose","C.Modi","D.monkeydluffy"))
answers=("B","C","C","C")
guesses=[]
score=0
question_num=0
for question in questions:
    print("-----------------------------------------")
    print(question)
    
    for option in options[question_num]:
        print(option)
    guess=(input("enter your answer:A,B,C,D:")).upper()
    guesses.append(guess)
    if guess==answers[question_num]:  
        print("CORRECT")
        score+=1  
    else:
        print("INCORRECT")
        print(f"{answers[question_num]} is the correct answer")
    question_num+=1  

print("answers:",answers)
print("guesses:",guesses)
score=int((score / len(questions))*100)  
print(f"your score is :{score}%")