import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials"
import bcrypt from "bcryptjs"
import dbConnect from "@/lib/dbConnect"
import UserModel from "@/model/User.model"




export const authOptions  = NextAuth({
    providers: [
        CredentialsProvider({
            id: "credentials",
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "text" },
                password: { label: "Password", type: "password" },
            },
            async authorize( credentials: any ): Promise<any> {
                await dbConnect()
                try {
                   const user = await UserModel.findOne({
                    $or: [
                        {email: credentials.identifier},
                        {username: credentials.identifier}
                    ]
                   }) 

                   if(!user) {
                    throw new Error("No user found with this email")
                   }

                   if(!user.isVerified){
                    throw new Error("Please verify your account first before login")
                   }

                   const isPasswordCorrect = await bcrypt.compare(credentials.password, user.password)

                   if(isPasswordCorrect){
                    return
                   } else {
                    throw new Error("Incorrect Password")
                   }
                } catch (err: any) {
                    throw new Error(err)
                }
            },
        })
    ],
})