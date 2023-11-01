const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;


const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require('nodemailer');
exports.signup = async(req, res) => {
    console.log('start login');
    console.log('this is password coming from the front ', req.body.password);
    if (!req.body.password || typeof req.body.password !== "string") {
        return res.status(400).send({ message: "Password is required and must be a string." });
    }

    try {
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, 8),
            roles: req.body.roles, // Default to 'user' if no roles provided
        });

        const savedUser = await user.save();

        const token = jwt.sign({ id: user.id }, config.secret, {
            algorithm: 'HS256',
            allowInsecureKeySizes: true,
            expiresIn: '10m', // 24 hours
        });

        const link = `http://localhost:3000/api/auth/verifemail?token=${token}`;

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

        verifyisemail(req.body.email, link);

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
        console.log(req.body.username)
        const user = await User.findOne({ username: req.body.username })
            .populate("roles", "-__v")
            .exec();
        console.log(user)
        if (!user) {
            return res.status(404).send({ message: "User Not found." });
        }
        const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

        if (!passwordIsValid) {
            return res.status(401).send({ message: "Invalid Password!" });
        }

        if (user.status === true) {
            const token = jwt.sign({ id: user.id }, config.secret, {
                algorithm: 'HS256',
                allowInsecureKeySizes: true,
                expiresIn: '10m', // 24 hours
            });

            const authorities = user.roles.map(role => "ROLE_" + role.name.toUpperCase());
            res.cookie('token', token, {
                maxAge: '10m', // 24 hours (in milliseconds)
                httpOnly: true, // Prevent JavaScript from accessing the cookie
            });
            req.session.token = token;

            res.status(200).send({
                id: user._id,
                username: user.username,
                email: user.email,
                roles: authorities,
                token: token
            });

        } else {
            return res.status(401).send({ message: "verifier votre compte" });

        }


    } catch (err) {
        console.error(err);
        res.status(500).send({ message: err.message || "An error occurred while signing in." });
    }
};

exports.forgetPassword = async(req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const token = jwt.sign({ id: user.id }, config.secret, {
            algorithm: 'HS256',
            allowInsecureKeySizes: true,
            expiresIn: '10m', // 24 hours
        });
        const link = `http://localhost:5173/reset-password?token=${token}`;

        function resetPasswordLink(email, link) {
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
        resetPasswordLink(email, link)

        res.json({ message: 'Password reset instructions sent to your email.' });
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }


}
exports.resetPassword = async(req, res) => {
    // const { token } = req.params;
    const newPassword = req.body.newPassword;
    const token = req.body.token;
    console.log('this is token', token);
    console.log(newPassword);

    try {



        const decodedToken = jwt.verify(token, config.secret);
        const userId = decodedToken.id;
        console.log(userId);

        const user = await User.findOne({ _id: userId });
        // const user = await User.findOne({ id });

        if (!user) {
            return res.status(400).json({ error: 'Lien de réinitialisation invalide ou expiré.' });
        }


        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findOneAndUpdate({ _id: userId }, { password: hashedPassword });


        return res.json({ success: true, message: 'Mot de passe réinitialisé avec succès.' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
}