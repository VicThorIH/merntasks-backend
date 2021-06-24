var bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Usuario = require('../models/Usuario');
const { validationResult } = require('express-validator');


exports.autenticarUsuario = async (req, res)  => {

    //Revisar si hay errores
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
        return res.status(400).json({ errores : errores.array() });
    }

    //Extraer el email y password del req
    const { email, password } = req.body;

    try {

        //Revisar que sea un usuario registrado
        let usuario = await Usuario.findOne({email});
        
        if(!usuario){
            return res.status(400).json({msg : 'El usuario no existe'});
        }

        //Revisar el password

        const passCorrecto = await bcrypt.compare(password, usuario.password);

        if(!passCorrecto){
            return res.status(400).json({msg : 'Password incorrecto'});
        }

        //Si todo es correcto
        //Crear y firmar el JSONWebToken
        const payload = {
            usuario : {
                id : usuario.id
            }
        };

        //Firmar el JWT
        jwt.sign(payload, process.env.SECRETA, {
            expiresIn : 3600 // 1Hora

        }, (error, token) => {
            if (error) throw error;
            
            //Mensaje de confirmacion
            res.json({token});
        });

    } catch (error) {
        console.log(error);
    }

}


//Obtiene que usuario esta autenticado
exports.usuarioAutenticado = async (req, res) => {
    try {
        const usuario = await Usuario.findById(req.usuario.id).select('-password');
        res.json(usuario);
    } catch (error) {
        console.log(error);
        res.status(500).json({msg: 'Hubo un error'});
    }
}