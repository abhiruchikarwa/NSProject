import msgs_pb2
import sys

person = msgs_pb2.Request()
person.name ="Ketan"
f = open('file.txt','wb')
f.write(person.SerializeToString())
f.close()