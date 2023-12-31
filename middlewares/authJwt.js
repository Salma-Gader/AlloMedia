const jwt = require("jsonwebtoken");
const config = require("../config/auth.config.js");
const db = require("../models/index.js");
const User = db.user;
const Role = db.role;

verifyToken = (req, res, next) => {
    let token = req.session.token;

    if (!token) {
        return res.status(403).send({ message: "No token provided!" });
    }

    jwt.verify(token,
        config.secret,
        (err, decoded) => {
            if (err) {
                return res.status(401).send({
                    message: "Unauthorized!",
                });
            }
            req.userId = decoded.id;
            next();
        });
};
isAdmin = async(req, res, next) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        const roles = await Role.find({ _id: { $in: user.roles } });

        for (let i = 0; i < roles.length; i++) {
            if (roles[i].name === "admin") {
                return next();
            }
        }

        return res.status(403).send({ message: "Require Admin Role!" });
    } catch (err) {
        return res.status(500).send({ message: err });
    }
};

isModerator = async(req, res, next) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        const roles = await Role.find({ _id: { $in: user.roles } });

        for (let i = 0; i < roles.length; i++) {
            if (roles[i].name === "moderator") {
                return next();
            }
        }

        return res.status(403).send({ message: "Require Moderator Role!" });
    } catch (err) {
        return res.status(500).send({ message: err });
    }
};


const authJwt = {
    verifyToken,
    isAdmin,
    isModerator,
};
module.exports = authJwt;