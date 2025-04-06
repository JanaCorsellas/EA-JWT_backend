import pkg from "jsonwebtoken";
const { sign, verify } = pkg;   //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "refresh.010101010101";

//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateToken = (id:string, additionalData = {}) => {
    const jwt = sign({id, ...additionalData}, JWT_SECRET, {expiresIn: '20s'});
    return jwt;
};

const generateRefreshToken = (id: string) => {
    const refreshToken = sign({ id }, REFRESH_SECRET, { expiresIn: '40s' });
    return refreshToken;
};


const verifyToken = (jwt: string) => {
    try {
        const isOk = verify(jwt, JWT_SECRET);
        return isOk;
    } catch (error) {
        return null;
    }
};

const verifyRefreshToken = (refreshToken: string) => {
    try {
        const payload = verify(refreshToken, REFRESH_SECRET);
        return payload;
    } catch (error) {
        return null;
    }
};

export { generateToken, generateRefreshToken, verifyToken, verifyRefreshToken };