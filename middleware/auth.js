const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
    //Leer el token del header
    const token = req.header('x-auth-token');
    console.log(token);

    //Revisar si no hay token
    if(!token){
        res.status(401).json({msg: 'No hay token, permiso no válido'});
    }

    //Validar el token
    try {
        //res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Credentials", true);
        res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
        res.header("Access-Control-Allow-Headers", 'Origin,X-Requested-With,Accept,content-type,application/json');
        const cifrado = jwt.verify(token, process.env.SECRETA);
        req.usuario = cifrado.usuario;
        next();
    } catch (error) {
        res.status(401).json({msg: 'Token no valido'});
    }

}