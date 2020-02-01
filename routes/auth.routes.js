const { Router } = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const {check, validationResult} = require('express-validator')
const config = require('config')
const router = Router()


// /api/auth/register 
router.post(
    '/register', 
    [
        check('email', 'email not valid').isEmail(),
        check('password', 'min password 6 simvolse')
        .isLength({ min: 6 })
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некоректные дынные при регистрации'
            })
        }
        

        const {email, password} = req.body

        const  candidate = await User.findOne({ email })
        if (candidate) {
            return res.status('400').json({ message: 'Такой пользователь уже существует'})
        }

        const hashedPassword = await bcrypt.hash(password, 29)
        const user = new User({ email: email, password: hashedPassword})
        await user.seve()

        res.status(201).json({ message: 'Пользователь создан'})


    } catch(e) {
        res.status(500).json({ message: 'ЧТО ТО ПОШЛО НЕ ТАК'})
    }
})

// /api/auth/login 
router.post(
    '/login',
    [
        check('email','Введите коректный email').normalizeEmail().isEmail()
        check('password', 'Введите пароль').exists()
    ], 
    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Некоректные дынные '
                })
            }

            const {email, password} = req.body
            const user = await User.findOne({ email})

            if (!user) {
                return res.status(400).json({ message: 'Пользователь не найден'})
            }

            const isMatch = await bcrypt.compare(password ,user.password)

            if (!isMatch) {
                return res.status(400).json({ message: 'Pssword not valid , try'})

            }
            const token = jwt.sign(
                { userId: user.id },
                config.get('jwtSecret'),
                { expiresIn: '1h'}
            )

            res.json({ token, userId: user.id })


            
            
    
        } catch(e) {
            res.status(500).json({ message: 'ЧТО ТО ПОШЛО НЕ ТАК'})
        }

})

module.exports = router