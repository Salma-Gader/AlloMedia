const mongoose = require("mongoose");

const User = mongoose.model(
    "User",
    new mongoose.Schema({
        username: String,
        email: String,
        password: String,
        status: {
            type: Boolean,
            default: false
        },
        roles: [{
            type: String,
            ref: "Role"
        }]
    })
);

module.exports = User;