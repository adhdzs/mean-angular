const response = require('express');
const Usuario = require('../models/Usuario');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');


const crearUsuario = async(req, res = response) => {

    const { email, name, password } = req.body;
    
    try {
        
        // Verificar email
        const usuario = await Usuario.findOne({ email });

        if ( usuario ) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo ya se encuentra registrado'
            });
        }

        // Crear usuario con el modelo
        const dbUser = new Usuario( req.body );

        // Hashear contraseña
        const salt = bcrypt.genSaltSync(10);
        dbUser.password = bcrypt.hashSync( password, salt );
        

        // Generar JWT
        const token = await generarJWT( dbUser.id, name );


        // Crear usuario de DB
        await dbUser.save();

        // Generar respuesta
        return res.status(201).json({
            ok: true,
            uid: dbUser.id,
            name,
            email,
            token
        });

    } catch ( error ) {
        console.log(error)
        return res.status(500).json({
            ok: false,
            msg: 'Error, contacte a un administrador!'
        });
    }

}

const loginUsuario = async(req, res = response) => {
    const { email, password } = req.body;
    
    try {

        const dbUser = await Usuario.findOne({ email });

        if ( !dbUser ) {
            return res.status(400).json({
                ok: false,
                msg: 'Correo no asociado a ninguna cuenta'
            });
        }

        // Confirmar password
        const validPassword = bcrypt.compareSync( password, dbUser.password )

        if ( !validPassword ) {
            return res.status(400).json({
                ok: false,
                msg: 'Password incorrecto'
            });
        }

        // Generar el JWT
        const token = await generarJWT( dbUser.id, dbUser.name );

        // Respuesta del servicio
        return res.json({
            ok: true,
            uid: dbUser.id,
            name: dbUser.name,
            email: dbUser.email,
            token
        });

    } catch (error) {
        console.log(error)
        return res.status(00).json({
            ok: false,
            msg: 'ERROR. Contacte a un administrador'
        });
    }

}

const revalidarToken = async(req, res = response) => {

    const { uid } = req;

    // Leer BD
    const dbUser = await Usuario.findById(uid);

    // Generar el JWT
    const token = await generarJWT( uid, dbUser.name );

    return res.json({
        ok: true,
        uid,
        name: dbUser.name,
        email: dbUser.email,
        token
    });

}


module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}