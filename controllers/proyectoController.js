const Proyecto = require('../models/Proyecto');
const { validationResult } = require('express-validator');

exports.crearProyecto = async (req, res) => {

    //Revisar si hay errores
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
        return res.status(400).json({ errores : errores.array() });
    }

    try {

        //Crear un nuevo proyecto
        const proyecto = new Proyecto(req.body);
        
        //Guardar el pryecto via JWT
        proyecto.creador = req.usuario.id;

        //Guardamos el pryecto
        proyecto.save();
        res.json(proyecto)
        
    } catch (error) {
        console.log(error);
        res.status(500).send('Hubo un error');
    }
}

//Obtiene todos los proyectos del usuario actual

exports.obtenerProyectos = async (req, res) => {
    try {

        const proyectos = await Proyecto.find({ creador: req.usuario.id }).sort({creado: -1});
        res.json({proyectos});

    } catch (error) {
        console.log(error);
        res.status(500).send('Hubo un error')
    }
}


//Actualiza un proyecto
exports.actualizarProyecto = async (req, res) => {
    //Revisar si hay errores
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
        return res.status(400).json({ errores : errores.array() });
    }

    //Extraer la informacion del proyecto
    const {nombre} = req.body; 
    const nuevoProyecto = {};

    if(nombre){
        nuevoProyecto.nombre = nombre;
    }

    try {
        //Revisar ID
        let proyecto = await Proyecto.findById(req.params.id);
        
        //Revisar que exista el proyecto
        if(!proyecto){
            return res.status(404).json({msg: 'Proyecto no encontrado'})
        }
        //Verificar el creador de l proyecto
        if(proyecto.creador.toString() !== req.usuario.id){
             return res.status(404).json({msg: 'No autorizado'})
        }
        //Actualizar
        proyecto = await Proyecto.findOneAndUpdate({_id: req.params.id}, {$set: nuevoProyecto}, {new: true});
        res.json({proyecto});
        
    } catch (error) {
        console.log(error);
        res.status(500).send('Error en el servidor');
    }

}


//Elimina un proyecto por su id

exports.eliminarProyecto = async(req, res) => {
    try {
        //Revisar ID
        let proyecto = await Proyecto.findById(req.params.id);
                
        //Revisar que exista el proyecto
        if(!proyecto){
            return res.status(404).json({msg: 'Proyecto no encontrado'})
        }
        //Verificar el creador de l proyecto
        if(proyecto.creador.toString() !== req.usuario.id){
            return res.status(404).json({msg: 'No autorizado'})
        }

        //Eliminar el proyecto
        await Proyecto.findOneAndRemove({_id: req.params.id});
        res.json({msg: 'Proyecto eliminado'});
    } catch (error) {
        console.log(error);
        res.status(500).send('Error en el servidor');
    }
}