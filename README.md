# FormFiller
Implements a server and client architecture whereby a client may create a user and store sensitive encrypted data, which may be used to automate the filling of forms. 

# Server 
Default server runs on localhost:8080. Configurations may be changed in ./server/server.py

Initialize the server by running:
```./setup.sh```

Run the server using the command: 
```python3 server.py```

# Client 

Run the client using the command:
```python3 client.py [server ip] [server port]```

Supported commands: 
`/adduser [username] [password]`:		Adds a user to the current system <br />

`/login [username] [password]`:      	Attempts to login with username and password <br />

`/getdata`:                           	Gets all data of the currently logged-in user<br />

`/deldata`:                          	Deletes all data of the currently logged-in user<br />

`/add "[key]" "[value]"`:     	        Adds the key-value pair to the data of the user, which is used to fill in form fields (e.g. /add "First name" "John")<br />

`/fill [input.pdf] [output.pdf]`:		Fills @input.pdf with the user's data and generates @output.pdf with all possible form fields filled. Input and output may be paths<br />

`/help `                             	Prints help message <br />
