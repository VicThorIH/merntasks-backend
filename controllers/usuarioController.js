var bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Usuario = require('../models/Usuario');
const { validationResult } = require('express-validator');

exports.crearUsuario = async (req, res) => {

    //Revisar si hay errores
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
        return res.status(400).json({ errores : errores.array() });
    }

    //Extraer emial y password
    const { email, password } = req.body;
    try {
        //Revisar que el usuario registrado sea unico

        let usuario = await Usuario.findOne({ email });

        if (usuario) {
            return res.status(400).json({msg : 'El Usuario ya existe'});
        }

        //Crea el nuevo usuario
        usuario = new Usuario(req.body);

        //Hashear el password

        await bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(password, salt, function(err, hash) {
                // Store hash in your password DB.
                usuario.password = hash;
                
                //Guardar Usuario
                usuario.save();

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

                
            });
        });

    } catch (error) {
        console.log(error);
        res.status(400).send("Hubo un error");
    }
}