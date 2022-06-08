import { ForbiddenException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import * as argon from "argon2";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) { }
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
            return this.signToken(user.id, user.email);

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

        return this.signToken(user.id, user.email);
    }
    async signToken(userId: number, email: string): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get("JWT_SECRET");

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret
        });
        return {
            access_token: token
        }

    }
}