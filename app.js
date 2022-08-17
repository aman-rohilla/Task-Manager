// Author - Aman-Rohilla@rohilla.co.in

const express = require('express')
const app = express()
require('dotenv').config()
require('express-async-errors')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrpyt = require('bcryptjs')
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 80
const JWT_SECRET     = process.env.JWT_SECRET     || 'thirty-two-character-long-secret' // 32byte long string
const SESSION_SECRET = process.env.SESSION_SECRET || 'SESSION_SECRET_CODE'
const COOKIE_SECRET  = process.env.COOKIE_SECRET  || 'COOKIE_SECRET_CODE'
const CONNECTION_STRING = process.env.MONGODB_CONNECTION_STRING || 'mongodb://localhost/task_manager_db'

app.use(cookieParser(COOKIE_SECRET))
app.use(express.static('./static'))
app.use(express.urlencoded({extended: false}))
app.use(express.json()) // get post data in req.body

const session = require('express-session');
const flash = require('connect-flash-plus')
app.use(session({
    secret: SESSION_SECRET,
    saveUninitialized: true,
    resave: true
}));
  
app.use(flash());

const nunjucks = require('nunjucks')
app.set('view engine', 'nunjucks')
nunjucks.configure(['templates/'], {
    autoescape: false,
    express: app
})

mongoose.connect(CONNECTION_STRING)
    .then(() => {
        console.log('CONNECTED to database...')
        app.listen(PORT, () => {
            console.log(`Server listening on port ${PORT}...`);
        })
    })
    .catch((err) => console.log(`FAILED to connect to database...\nerror : ${err}`))


const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, `Name can't be empty`],
        minlength: 2,
        maxlength: 50,
    }, 
    email: {
        type: String,
        required: [true, `Email can't be empty`],
        minlength: 6,
        maxlength: 50,
        match: [/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, `Email format is invalid`],
        unique: true
    },
    password: {
        type: String,
        required: [true, `Password can't be empty`],
        minlength: 8,
    },
}, {timestamps: true})

UserSchema.methods.generateToken = function() {
    return jwt.sign({userID: this._id, username: this.name}, JWT_SECRET, {expiresIn: '30d'})
}

const TaskSchema = new mongoose.Schema({
    name: {
        type: String,
        // required: true,
        required: [true, 'Error message if this field was not present'],
        trim: true,
        maxlength: [30, 'More than 30 characters are not allowed in name field']
    },
    completed: {
        type: Boolean,
        default: false
    },
    taskUserID: {
        type: mongoose.Types.ObjectId,
        ref: 'User', // the name of model to which the taskUserID belongs
        required: true
    }
}, {timestamps: true})


const User = mongoose.model('User', UserSchema)
const Task = mongoose.model('Task', TaskSchema)

const categories = ['primary', 'secondary', 'success', 'danger', 'warning', 'info', 'light', 'dark']


const apiMiddleware = (req, res, next) => {
    req.api = true
    next()
}
app.use('/api', apiMiddleware)


const flashMsg = (req, message, category) => {
    req.flash('msgs', {message, category})
}

const webAuthenticationMiddleware = (req, res, next) => {
    if(req.api)
        return next()
        
    try {
        const userToken = req.signedCookies.token
        if(!userToken) {
            flashMsg(req, 'You are not logged in', 'danger')
            return res.redirect('/')
        }
        const decodedPayload = jwt.verify(userToken, JWT_SECRET) 
        const {userID, username} = decodedPayload
        req.user = {userID, username} // associate the user to request which can be accessed in request handlers
        next()
    } catch(error) {
        flashMsg(req, 'You are not logged in', 'danger')
        return res.redirect('/')
    }
}

const apiAuthenticationMiddleware = (req, res, next) => {
    if(req.url.startsWith('/auth/token'))
        return next()

    try {
        if(!req.headers.authorization) {
            return res.json({status: 'error', msg: 'No token provided in authorization header'})
        }
        if(!req.headers.authorization.startsWith('Bearer '))
            return res.json({status: 'error', msg: 'Bearer token type was expected'})

        const userToken = req.headers.authorization.split(' ')[1]
        const decodedPayload = jwt.verify(userToken, JWT_SECRET) 
        const {userID, username} = decodedPayload
        req.user = {userID, username}
        next()
    } catch(error) {
        return res.json({status: 'error', msg: 'Error with token'})
    }
}
app.use('/api', apiAuthenticationMiddleware)

const userDecoderMiddleware = (req, res, next) => {
    try {
        const userToken = req.signedCookies.token
        if(!userToken) return next()
        const decodedPayload = jwt.verify(userToken, JWT_SECRET) 
        const {userID, username} = decodedPayload
        req.user = {userID, username}

        next()
    } catch(error) {
        next()
    }
}



/* API Routes

POST    /api     - create a task
GET     /api/:id - get a task by id
PATCH   /api/:id - update a task by id
DELETE  /api/:id - delete a task by id

GET     /api     - get all tasks
DELETE  /api     - delete all tasks
PATCH   /api     - mark all tasks as completed=true/false

GET     /api/auth/token - get Bearer type access token
*/



app.post('/signup', userDecoderMiddleware, async (req, res) => {
    if(req.user) {
        flashMsg(req, 'You are already logged in', 'info')
        return res.redirect('/')
    }

    const {name, email, password} = req.body
    const salt = await bcrpyt.genSalt(10); // salt is randomly generated bytes
    const hashedPassword = await bcrpyt.hash(password, salt);

    try {
        const user = await User.create({name, email, password: hashedPassword})
        const token = user.generateToken()
        const oneDay = 1000 * 60 * 60 * 24;
        res.cookie('token', token, {
            httpOnly: true,
            expires: new Date(Date.now() + 30*oneDay),
            // secure: true,
            signed: true,
            // path: '/',
        });
        flashMsg(req, 'Your account was created successfully!', 'success');
        res.redirect('/')
    } catch (err) {
        res.render('signup.html', {messages: [
            {category: 'danger', messages: [`Something went wrong`]}
        ]})
    }
})

app.get('/signup', userDecoderMiddleware, (req, res) => {
    if(req.user) {
        flashMsg(req, 'You are already logged in', 'info')
        return res.redirect('/')
    }
    return res.render('signup.html')
})

app.post('/login', userDecoderMiddleware, async (req, res) => {
    if(req.user) {
        flashMsg(req, 'You are already logged in', 'info')
        return res.redirect('/')
    }

    const {email, password} = req.body
    if(!email || !password) {
        flashMsg(req, 'Email and/or password is empty', 'danger')
        return res.redirect('/')
    }

    const user = await User.findOne({email})
    if(!user) {
        flashMsg(req, `${email} is not registered`, 'danger')
        return res.redirect('/')
    }
    if(! await bcrpyt.compare(password, user.password)) {
        flashMsg(req, `Password is incorrect`, 'danger')
        return res.redirect('/')
    }

    const token = user.generateToken() // token has userID and username
    const oneDay = 1000 * 60 * 60 * 24;
    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 30*oneDay),
        // secure: true,
        signed: true,
        path: '/',
    });
    flashMsg(req, 'Login Successful!', 'success')
    res.redirect('/')
})

app.get('/logout', userDecoderMiddleware, async (req, res) => {
    if(req.user) {
        flashMsg(req, 'Logged out Successfully', 'success')
    }
    res.clearCookie('token');
    res.redirect('/')
})


app.post(['/create-new-task', '/api'], webAuthenticationMiddleware, async (req, res) => {
    const task = await Task.create({
        name: req.body.name.trim(),
        completed: req.body.completed,
        taskUserID: req.user.userID
    })

    if (req.api)
        return res.json({status: 'success', msg: 'Task created', task})

    res.redirect('/')
})

app.get(['/', '/api'], userDecoderMiddleware, async (req, res) => {
    if (!req.user) {
        if (req.api)
            return res.json({status: 'error', msg: 'Unauthorized', tasks: null})
        else
            return res.render('home_login.html', {messages: req.flash('msgs')})
    }

    const user = await User.findById({_id: req.user.userID})

    if (!user) {
        if (req.api)
            return res.json({status: 'error', msg: 'Mysterious activity on client side', tasks: null})
        else 
            return res.render('home_login.html', {messages: req.flash('msgs')})
    }
    
    const tasks = await Task.find({taskUserID: req.user.userID})
    if (!tasks.length) {
        if(! req.api)
            return res.render('home_no_task.html', {messages: req.flash('msgs'), user})
    }
    
    if (req.api)
        return res.json({status: 'success', msg: 'none', tasks, numTasks: tasks.length})

    let i=0;
    const taskObject = tasks.reverse().map((task) => {
        const category = categories[i%categories.length]
        i++
        return {id: task.id, name: task.name, completed: task.completed, category}
    })
    
    return res.render('home.html', {messages: req.flash('msgs'), taskObject, user})
})


app.get('/delete-task/:id', webAuthenticationMiddleware, async (req, res) => {
    await Task.findByIdAndDelete({_id: req.params.id, taskUserID: req.user.userID})
    res.redirect('/')
})

app.get('/update-all/:operation', webAuthenticationMiddleware, async (req, res) => {

    let op = req.params.operation
    if (op == 'delete') await Task.deleteMany({taskUserID: req.user.userID})
    else {
        await Task.updateMany(
            {taskUserID: req.user.userID},
            {completed: op == 'complete' ? true : false}
        )
    }

    res.redirect('/')
})

app.get('/complete-task/:id', webAuthenticationMiddleware, async (req, res) => {

    const task = await Task.findById({_id: req.params.id, taskUserID: req.user.userID})
    await task.update({completed: !(task.completed)})
    res.redirect('/')
})

app.post('/edit-task/:id', webAuthenticationMiddleware, async (req, res) => {
    const task = await Task.findById({_id: req.params.id, taskUserID: req.user.userID})
    await task.update({name: req.body.name}, {runValidators:true})
    res.redirect('/')
})




// api delete all tasks
app.delete('/api', async (req, res) => {
    const tasks = await Task.deleteMany({taskUserID: req.user.userID}, {returnDocument: true})
    return res.json({status: 'success', msg: tasks.deletedCount? 'Tasks deleted' : 'No tasks to delete'})
})

// api mark all tasks as completed or uncompleted
app.patch('/api', async (req, res) => {
    const tasks = await Task.updateMany(
        {taskUserID: req.user.userID},
        {completed: req.body.completed},    )
    return res.json({status: 'success', msg: tasks.matchedCount ? 'Tasks Updated' : 'No tasks to update'})
})

// api get single task by id
app.get('/api/:taskID', async (req, res) => {
    const task = await Task.findOne({_id: req.params.taskID, taskUserID: req.user.userID})
    if(!task) {
        return res.json({status: 'error', msg: `No task found having id = ${req.params.taskID}`, task})
    }
    return res.json({status: 'success', msg: 'none', task})
})

// api update task by ID
app.patch('/api/:taskID', async (req, res) => {
    const task = await Task.findOneAndUpdate(
        {_id: req.params.taskID, taskUserID: req.user.userID}, // find the object
        req.body, // updates object,
        {new: true, runValidators: true}
    )

    if(!task) {
        return res.json({status: 'error', msg: `No task found having id = ${req.params.taskID}`, task})
    }
    return res.json({status: 'success', msg: 'Task Updated'})
})

// api delete task by id
app.delete('/api/:taskID', webAuthenticationMiddleware, async (req, res) => {
    const task = await Task.findOneAndDelete({_id: req.params.taskID, taskUserID: req.user.userID})
    if(!task) {
        return res.json({status: 'error', msg: `No task found having id = ${req.params.taskID}`, task: null})
    }
    return res.json({status: 'success', msg: 'Task deleted', task})
})

app.get('/api/auth/token', async (req, res) => {
    let token = null;
    const {email, password} = req.body
    if(!email || !password) {
        return res.json({status: 'error', msg: 'Email and/or password is/are empty', token})
    }

    const user = await User.findOne({email})
    if(!user) {
        return res.json({status: 'error', msg: `${email} is not registered`, token})
    }
    if(! await bcrpyt.compare(password, user.password)) {
        return res.json({status: 'error', msg: 'Password is incorrect', token})        
    }

    token = user.generateToken()
    return res.json({status: 'success', msg: 'Token generated', tokenType: 'Bearer', token})
})


const errorHandlerMiddleware = (err, req, res, next) => {
    if(req.api)
        return res.json({status: 'error', msg: 'Unknown Error'})
    
    return res.json({ msg: 'Something went wrong, please try again' })
}
const notFound = (req, res) => {
    if(req.api)
        return res.json({status: 'error', msg: `Route doesn't exist`})
    
    return res.status(404).send('<h2>Route does not exist</h2>')
}

app.use(errorHandlerMiddleware)
app.use(notFound)


// app.listen(PORT, () => {
//     console.log(`Server listening on port ${PORT}...`);
// })
