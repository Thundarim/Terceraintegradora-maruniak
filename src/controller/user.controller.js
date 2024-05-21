const UserModel = require("../dao/models/users.model.js");
const CartModel = require("../dao/models/cart.model.js");
const jwt = require("jsonwebtoken");
const { createHash, isValidPassword } = require("../utils/hashBcrypt.js");
const UserDTO = require("../dto/user.dto.js");
const { generateResetToken } = require("../utils/tokenreset.js");
const EmailManager = require("../services/email.js");
const emailManager = new EmailManager();
const swal = require("sweetalert2");

class UserController {
    async requestPasswordReset(req, res) {
        const { email } = req.body;

        try {
            const user = await UserModel.findOne({ email });
            if (!user) {
                return res.status(404).send("Usuario no encontrado");
            }
            const token = generateResetToken();
            user.resetToken = {
                token: token,
                expiresAt: new Date(Date.now() + 3600000)
            };
            await user.save();
            await emailManager.enviarCorreoRestablecimiento(email, user.first_name, token);
            return res.redirect('/password');
        } catch (error) {
            console.error(error);
            res.status(500).send("Error interno del servidor");
        }
    }

    async resetPassword(req, res) {
        const { email, password, token } = req.body;

        try {
            const user = await UserModel.findOne({ email });
            if (!user) {
                return res.render("passwordcambio", { error: "Usuario no encontrado" });
            }
            const resetToken = user.resetToken;
            if (!resetToken || resetToken.token !== token) {
                return res.render("passwordreset", { error: "El token de restablecimiento de contraseña es inválido" });
            }
            const now = new Date();
            if (now > resetToken.expiresAt) {
                return res.redirect("/passwordcambio");
            }
            if (isValidPassword(password, user)) {
                return res.render("passwordcambio", { error: "La nueva contraseña no puede ser igual a la anterior" });
            }
            user.password = createHash(password);
            user.resetToken = undefined;
            await user.save();
            return res.redirect("/login");
        } catch (error) {
            console.error(error);
            return res.status(500).render("passwordreset", { error: "Error interno del servidor" });
        }
    }
    async cambiarRolPremium(req, res) {
        try {
            const { uid } = req.params;
    
            const user = await UserModel.findById(uid);
    
            if (!user) {
                return res.status(404).json({ message: 'Usuario no encontrado' });
            }
    
            const nuevoRol = user.role === 'usuario' ? 'premium' : 'usuario';
    
            const actualizado = await UserModel.findByIdAndUpdate(uid, { role: nuevoRol }, { new: true });
            res.json(actualizado);
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Error interno del servidor' });
        }
    }
}

module.exports = UserController;