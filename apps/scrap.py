uri = "mongodb+srv://yangjunwon1309:MGACKDnRT2ZrLNBz@mad0.uejylnk.mongodb.net/?retryWrites=true&w=majority"
# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
# Send a ping to confirm a successful connection
try:

except Exception as e:
    print(e)