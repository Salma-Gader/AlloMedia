exports.userController = {
    allAccess: (req, res) => {
        res.status(200).send("Public Content.");
    },
    userBoard: (req, res) => {
        res.status(200).send("User Content.");
    },
    deliveryBoard: (req, res) => {
        res.status(200).send("Delivery Content.");
    },
    adminBoard: (req, res) => {
        res.status(200).send("Admin Content.");
    },
};