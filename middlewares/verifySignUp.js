const db = require("../models");
const ROLES = db.ROLES;
const User = db.user;

checkDuplicateUsernameOrEmail = async(req, res, next) => {
    // Username
    console.log('inside middleware')
        /*await User.findOne({
            username: req.body.username
        }).exec((err, user) => {
            if (err) {
                res.status(500).send({ message: err });
                return;
            }

            if (user) {
                res.status(400).send({ message: "Failed! Username is already in use!" });
                return;
            }

            // Email
            console.log('inside middleware email')
            User.findOne({
                email: req.body.email
            }).exec((err, user) => {
                if (err) {
                    res.status(500).send({ message: err });
                    return;
                }

                if (user) {
                    res.status(400).send({ message: "Failed! Email is already in use!" });
                    return;
                }

                next();
            });
        });*/
    try {
        // Vérification du nom d'utilisateur
        const existingUsername = await User.findOne({ username: req.body.username });
        if (existingUsername) {
            return res.status(400).send({ message: "Failed! Username is already in use!" });
        }

        console.log('tototootot')

        // Vérification de l'e-mail
        const existingEmail = await User.findOne({ email: req.body.email });
        if (existingEmail) {
            return res.status(400).send({ message: "Failed! Email is already in use!" });
        }

        next();
    } catch (err) {
        res.status(500).send({ message: err });
    }
};

// checkRolesExisted = (req, res, next) => {
//     if (req.body.roles) {
//         for (let i = 0; i < req.body.roles.length; i++) {

//             if (!ROLES.includes(req.body.roles[i])) {
//                 res.status(400).send({
//                     message: `Failed! Role ${req.body.roles[i]} does not exist!`
//                 });
//                 return;
//             }
//         }
//     }
//     console.log('success rolle')
//     next();
// };

const verifySignUp = {
    checkDuplicateUsernameOrEmail,
    // checkRolesExisted
};

module.exports = verifySignUp;