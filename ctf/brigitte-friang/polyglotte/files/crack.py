codexor = [0x69,0x3F,0x6F,0x38,0x68,0x3E,0x06,0x69]
egal = [52,111,105,63,111,56,104,62,6,105]
result = [0,0,0,0,0,0,0,0,0,52]

i = 1
while(i < 9):
    t = egal[i]^codexor[i-1]
    t = t ^ result[len(result)-i]
    result[len(result)-i-1] = t
    i+=1

t = egal[9]
t = t ^ result[1]
result[0]=t

print("Result : ", end="")
for c in result:
    print(chr(c), end="")
print("")

