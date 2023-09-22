const jwt=require("jsonwebtoken");
require("dotenv").config();

exports.auth=(req,res,next)=>{
    try{
        const token=req.body.token;
        if(!token){
            return res.status(401).json({
                success:false,
                message:"Token Missing",
            });
        }
        try{
            const payload=jwt.verify(token, process.env.JWT_SECRET);
            console.log(payload);
            req.user=payload;
        }catch(error){
            return res.status(401).json({
                success:false,
                message:'token is invalid',
            });
        }
        next();

    }catch(error){
        return res.status(401).json({
            success:false,
            message:"Something is wrong while verifying token"
        })
    }
}

exports.isStudent=(req,res,next)=>{
    try{
        if(req.user.role!=="student"){
            return res.status(401).json({
                success:false,
                message:"This is protected students",
            });
        }
        next();
    }catch(error){
        return res.status(500).json({
            success:false,
            message:"User Role is not Matching",
        })
    }
}

exports.isAdmin=(req,res,next)=>{
    try{
        if(req.user.role!=="Admin"){
            return res.status(401).json({
                success:false,
                message:"This is Protected Route for Admin",
            });
        }
        next();
    }catch(error){
        return res.status(500).json({
            success:false,
            message:"Route not matching",
        });
    }
}
