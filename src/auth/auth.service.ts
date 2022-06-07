import { Delete, ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) { }
    async signup(dto: AuthDto) {
        // generate hash password
        const hash = await argon.hash(dto.password);
        // save user to database
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });
            delete user.hash;
            // return  saved user
            return user;
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === "P2002") {
                    throw new ForbiddenException("Credentials taken");
                }
            }
        }
    }
    async signin(dto: AuthDto) {
        // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });
        // if user not found throw error
        if (!user) throw new ForbiddenException("Credentials not found")
        // compare password 
        const pwMatches = await argon.verify(user.hash, dto.password);
        // if password not match throw error
        if (!pwMatches) throw new ForbiddenException("Credentials not found")
        // send back the user
        delete user.hash;
        return user;
    }
}