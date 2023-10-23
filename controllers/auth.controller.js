const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require('nodemailer');
exports.signup = async(req, res) => {
    console.log('start login')
    if (!req.body.password || typeof req.body.password !== "string") {
        return res.status(400).send({ message: "Password is required and must be a string." });
    }

    try {
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, 8),
            roles: req.body.roles

        });

        const savedUser = await user.save();

        if (req.body.roles) {
            const roles = await Role.find({ name: { $in: req.body.roles[0] } });

            user.roles = roles.map((role) => role._id);
            await user.save();
        } else {
            const role = await Role.findOne({ name: "user" });
            user.roles = [role._id];
            await user.save();
        }
        const token = jwt.sign({ id: user.id }, config.secret, {
            algorithm: 'HS256',
            allowInsecureKeySizes: true,
            expiresIn: 86400, // 24 hours
        });

        const link = `http://localhost:3000/api/auth/verifemail?token=${token}`

        function verifyisemail(email, link) {
            const transport = nodemailer.createTransport({
                host: "sandbox.smtp.mailtrap.io",
                port: 2525,
                auth: {
                    user: "0cc5d139b54c49",
                    pass: "41210e5c586c8c"
                }
            });

            const mailOptions = {
                from: 'vindication@enron.com',
                to: email,
                subject: 'Invoices due',
                text: 'Dudes, we really need your money.',
                html: `
                <p>Your account is not verified yet. Click the link below to verify your account:</p>
                <a href=${link}>Verify Account</a>
                `
            };

            transport.sendMail(mailOptions, function(error, info) {
                if (error) {
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        }

        verifyisemail(req.body.email, link)

        res.send({ message: "User was registered successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).send({ message: err.message || "An error occurred while registering the user." });
    }






};
exports.verifyEmail = async(req, res) => {
    const token = req.query.token;

    try {
        const decoded = jwt.verify(token, config.secret);
        const userId = decoded.id;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send("User not found");
        }

        user.status = true;
        await user.save();

        res.send("Email verified");
    } catch (err) {
        res.status(401).send("Unauthorized");
    }
};


exports.signin = async(req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username })
            .populate("roles", "-__v")
            .exec();

        if (!user) {
            return res.status(404).send({ message: "User Not found." });
        }

        const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

        if (!passwordIsValid) {
            return res.status(401).send({ message: "Invalid Password!" });
        }

        const token = jwt.sign({ id: user.id }, config.secret, {
            algorithm: 'HS256',
            allowInsecureKeySizes: true,
            expiresIn: 86400, // 24 hours
        });

        const authorities = user.roles.map(role => "ROLE_" + role.name.toUpperCase());

        req.session.token = token;

        res.status(200).send({
            id: user._id,
            username: user.username,
            email: user.email,
            roles: authorities,
            token: token
        });
    } catch (err) {
        console.error(err);
        res.status(500).send({ message: err.message || "An error occurred while signing in." });
    }
};

exports.signout = async(req, res) => {
    try {
        req.session = null;
        return res.status(200).send({ message: "You've been signed out!" });
    } catch (err) {
        this.next(err);
    }
};

// exports.resetPassword = async(req, res) => {
//     const { token } = req.params;
//     const { password } = req.body;

//     try {
//         const decoded = jwt.verify(token, 'your-secret-key');

//         const user = await User.findOne({
//             email: decoded.email,
//             resetToken: token,
//             resetTokenExpiration: { $gt: new Date() },
//         });

//         if (!user) {
//             return res.status(401).json({ message: 'Invalid or expired token' });
//         }
//         const hashedPassword = await bcrypt.hash(password, 10);
//         user.password = hashedPassword;
//         user.resetToken = null;
//         user.resetTokenExpiration = null;

//         await user.save();

//         res.status(200).json({ message: 'Password reset successfully' });
//     } catch (error) {
//         res.status(401).json({ message: 'Invalid or expired token' });
//     }
// };