import pkg from "jsonwebtoken";
import { IUser } from "../modules/users/user_models.js";
import { MongoDBCollectionNamespace } from "mongodb";
const { sign, verify } = pkg;   //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";

interface AccesTkn {
    id: string | undefined,
    mail: string,
    isRoot: boolean,
}
//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateAccessToken = (user: IUser) => {
    const AccesTkn : AccesTkn = {
        id: user._id?.toString(),
        mail: user.email,
        isRoot: false,
    };
    if (user.name === "Marcel")  {
        AccesTkn.isRoot = true;
    };
    const jwt = sign(AccesTkn, JWT_SECRET, {expiresIn: '10s'});
    return jwt;
};

const verifyTokenAccess = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET) as AccesTkn;
    return isOk;
};

const verifyTokenRefresh = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET) as string;
    return isOk;
};

const generateRefreshToken = (id: string) => {
    const refreshToken = sign({ id }, JWT_SECRET, { expiresIn: '1d' });
    return refreshToken;
};


export { generateAccessToken, verifyTokenAccess, generateRefreshToken, verifyTokenRefresh };