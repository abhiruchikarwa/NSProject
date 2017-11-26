import msgs_pb2
import sys

person = msgs_pb2.Request()

f = open('file.txt','rb')
person.ParseFromString(f.read())
f.close()

print("The name is :", person.name)