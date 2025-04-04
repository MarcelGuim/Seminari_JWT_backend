import { Request, Response, NextFunction } from "express";
import { verifyTokenAccess, verifyTokenRefresh } from "../utils/jwt.handle.js";
import { JwtPayload } from "jsonwebtoken";

interface RequestExt extends Request {
    user?: string | JwtPayload;
}

const checkJwt = (req: RequestExt, res: Response, next: NextFunction) => {
    try {
        const jwtByUser = req.headers.authorization || null;
        const jwt = jwtByUser?.split(' ').pop(); // ['Bearer', '11111'] -> ['11111']
        console.log(jwt);
        const isUser = verifyTokenAccess(`${jwt}`);
        const isUser2 = verifyTokenRefresh(`${jwt}`);
        if (!isUser && !isUser2) {
            return res.status(401).send("NO_TIENES_UN_JWT_VALIDO"); // return para evitar llamar a next()
        }
        else if (isUser) {
            req.user = isUser
        }
        else if (isUser2) {
            req.user = isUser2
        } 
        next(); // Solo si el token es válido, pasa al siguiente middleware
    } catch (e) {
        console.error("Error en checkJwt:", e);
        return res.status(401).send("SESSION_NO_VALID"); // Asegúrate de detener con return
    }
};

export { checkJwt };
