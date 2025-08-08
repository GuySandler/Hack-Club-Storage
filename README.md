# Hack Club YSWS Storage API
### an api to store ysws and users (for hosting ysws) that also has querry features and logins
### made for endpointer



### /public will be a client side for the API but sadly it doesn't count that as time


### /api:
1. make a .env based on .env.example and make your hash key (if you don't have one run ```node -e "console.log(require('crypto').randomBytes(64).toString('hex'))" to generate jwt secrete```)
2. run ```npm i```
3. run ```npm start``` for a normal run or ```npm run dev``` for auto reload
4. register and open database.db in a db editor to give yourself admin. To add more admins you can use the API but the first one has to be done manually
5. go to the running link (from the console) and go to /docs to read the api docs

16 total paths:
- 8 GET
- 3 POST
- 2 DELETE
- 3 PUT
- 8 Protected paths of different permissions

Some paths require to be logged in, some require you to be the owner of the YSWS (to make changes), and some require admin permissions (role 1)
