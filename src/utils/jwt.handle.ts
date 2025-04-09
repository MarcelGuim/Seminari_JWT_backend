import pkg from "jsonwebtoken";
import User, { IUser } from "../modules/users/user_models.js";
import { MongoDBCollectionNamespace } from "mongodb";
const { sign, verify } = pkg;   //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";

interface Tkn {
    id: string | undefined,
    isRoot: boolean,
}
//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateAccessToken = (user: IUser) => {
    const AccesTkn : Tkn = {
        id: user._id?.toString(),
        isRoot: false,
    };
    if (user.name === "Marcel")  {
        AccesTkn.isRoot = true;
    };
    const jwt = sign(AccesTkn, JWT_SECRET, {expiresIn: '5s'});
    return jwt;
};

const verifyTokenAccess = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET) as Tkn;
    return isOk as Tkn;
};

const verifyTokenRefresh = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET) as Tkn;
    return isOk as Tkn;
};

const generateRefreshToken = async (id: string) => {
    const user = await User.findById(id);
    const RefreshTkn : Tkn = {
        id: id,
        isRoot: false,
    };
    if (!user) return null
    if (user.name === "Marcel" )  {
        RefreshTkn.isRoot = true;
    };
    const jwt = sign(RefreshTkn, JWT_SECRET, {expiresIn: '1d'});
    return jwt;
};


export { generateAccessToken, verifyTokenAccess, generateRefreshToken, verifyTokenRefresh };