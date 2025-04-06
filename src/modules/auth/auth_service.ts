import { encrypt, verified } from "../../utils/bcrypt.handle.js";
import { generateRefreshToken, generateToken, verifyRefreshToken } from "../../utils/jwt.handle.js";
import User, { IUser } from "../users/user_models.js";
import { Auth } from "./auth_model.js";
import jwt from 'jsonwebtoken';
import axios from 'axios';

const registerNewUser = async ({ email, password, name, age }: IUser) => {
    const checkIs = await User.findOne({ email });
    if(checkIs) return "ALREADY_USER";
    const passHash = await encrypt(password);
    const registerNewUser = await User.create({ 
        email, 
        password: passHash, 
        name, 
        age });
    return registerNewUser;
};

const loginUser = async ({ email, password }: Auth) => {
    const checkIs = await User.findOne({ email });
    if(!checkIs) return "NOT_FOUND_USER";

    const passwordHash = checkIs.password; //El encriptado que viene de la bbdd
    const isCorrect = await verified(password, passwordHash);
    if(!isCorrect) return "INCORRECT_PASSWORD";

    const additionalData = {
        name: checkIs.name,
        role: checkIs.role || 'user' // Asumiendo que tienes un campo role o algo similar
    };

    const token = generateToken(checkIs.email, additionalData);
    const refreshToken = generateRefreshToken(checkIs.email);

    checkIs.refreshToken = refreshToken; // Guardar el refresh token en la base de datos
    await checkIs.save(); // Guardar el usuario actualizado
    const data = {
        token,
        refreshToken,
        user: checkIs
    }
    return data;
};

const googleAuth = async (code: string) => {

    try {
        console.log("Client ID:", process.env.GOOGLE_CLIENT_ID);
        console.log("Client Secret:", process.env.GOOGLE_CLIENT_SECRET);
        console.log("Redirect URI:", process.env.GOOGLE_OAUTH_REDIRECT_URL);
    
        if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_OAUTH_REDIRECT_URL) {
            throw new Error("Variables de entorno faltantes");
        }

        interface TokenResponse {
            access_token: string;
            expires_in: number;
            scope: string;
            token_type: string;
            id_token?: string;
        }

        const tokenResponse = await axios.post<TokenResponse>('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URL,
            grant_type: 'authorization_code'
        });

        const access_token = tokenResponse.data.access_token;
        console.log("Access Token:", access_token); 
        // Obtiene el perfil del usuario
        const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
            params: { access_token},
            headers: { Accept: 'application/json',},
            
        });

        const profile = profileResponse.data as {name:string, email: string; id: string };
        console.log("Access profile:", profile); 
        // Busca o crea el usuario en la base de datos
        let user = await User.findOne({ 
            $or: [{name: profile.name},{ email: profile.email }, { googleId: profile.id }] 
        });

        if (!user) {
            const randomPassword = Math.random().toString(36).slice(-8);
            const passHash = await encrypt(randomPassword);
            user = await User.create({
                name: profile.name,
                email: profile.email,
                googleId: profile.id,
                password: passHash,
            });
        }

        // Genera el token JWT
        const token = generateToken(user.email);

        console.log(token);
        return { token, user };

    } catch (error: any) {
        console.error('Google Auth Error:', error.response?.data || error.message); // Log detallado
        throw new Error('Error en autenticación con Google');
    }
};

const refreshUserToken = async (refreshToken: string) => {
    try {
        // Verificar refresh token
        const payload: any = verifyRefreshToken(refreshToken);
        if (!payload) return "INVALID_REFRESH_TOKEN";

        // Buscar usuario por email (que está en el payload)
        const user = await User.findOne({ email: payload.id });
        if (!user) return "USER_NOT_FOUND";

        // Verificar que el refresh token coincide con el almacenado
        if (user.refreshToken !== refreshToken) return "REFRESH_TOKEN_EXPIRED";

        // Datos adicionales para el token
        const additionalData = {
            name: user.name,
            role: user.role || 'user'
        };

        // Generar nuevo access token
        const newToken = generateToken(user.email, additionalData);
        
        return {
            token: newToken,
            user
        };
    } catch (error) {
        console.error("Error refreshing token:", error);
        return "ERROR_REFRESHING_TOKEN";
    }
};

export { registerNewUser, loginUser, googleAuth, refreshUserToken };