const Express = require('express')
const App = Express()
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs')
const mysql = require('mysql')
const jwt = require('jsonwebtoken')
const config = require('./config')
App.set('api_secret_key',config.api_secret_key)
App.use(bodyParser.json())
App.use(bodyParser.urlencoded({extended : true}))
const con = mysql.createPool({
    host:"localhost",
    user:"root",
    password:"emcobase35",
    connectionLimit : 10,
    database:'crudexpress'
})

const verifyToken = (request,response,next)=>{
    const token = request.headers['x-access-token'] || request.body.token || request.query.token
    if(!token)
        response.json({
            "title":"error",
            "body":"No token provided!"
        })
    else{
        jwt.verify(token,request.app.get('api_secret_key'),(error,decode)=>{
            if(error)
                response.json({
                    "title":"error",
                    "body":error
                })
            else{
                request.decode = decode
                next()
            }
        })
    }
}

App.get('/',(request,response)=>{
    response.json("Everyone can access here.")
})

App.post('/login',(request,response)=>{
    const {username,password} = request.body
    con.query('select * from users where Username = ?',[username],(error,result)=>{
        if(error)
            response.json({
                "title":"error",
                "body":error
            })
        if(result.length === 0)
            response.json("Wrong username")
        else
            bcrypt.compare(password,result[0]["Password"])
                .then(result => {
                    if(!result)
                        response.json("Wrong password")
                    else{
                        const payload = {
                            username
                        }
                        const token = jwt.sign(payload,request.app.get('api_secret_key'),{expiresIn : 720})
                        response.json({
                            "title":"successfully login!",
                            "body":token
                        })
                    }
                })
                .catch(error => {
                    response.json({
                        "title":"error",
                        "body":error
                    })
                })
    })
})
App.post('/register',(request,response)=>{
    const {username,password,email} = request.body
    con.query('select * from users where Username=?',[username],(error,result)=>{
        if(error)
            response.json({
                "title":"error",
                "body":error
            })
        if(result.length > 0)
            response.json("This username is already exist!")
        else
            bcrypt.hash(password,10,(error,hash)=>{
                if(error)
                    response.json({
                        "title":"error",
                        "body":error
                    })
                else
                    con.query("insert into users" +
                        "(Username,Password,Email,emailConfirmed,userrole) values(?,?,?,?,?)",
                        [username,hash,email,false,'user'],(error,result)=>{
                            if(error)
                                response.json({
                                    "title":"error",
                                    "body":error
                                })
                            response.json({
                                "title":"success",
                                "body":"Thanks for your register!",
                                "details":result
                            })
                        })
            })
    })
})
App.post('/admin/login',async()=>{

})
App.post('/admin/register',async()=>{

})
App.get('/user/index',verifyToken,(request,response)=>{
    response.json({
        "title":"index page",
        "body":"you are in the index page for users!",
        "token":request.decode
    })
})
App.get('/user/account',()=>{

})
App.get('/manager/index',()=>{

})
App.get('/manager/account',()=>{

})
App.listen('3000',()=>{
    console.log("3000 listening..")
})