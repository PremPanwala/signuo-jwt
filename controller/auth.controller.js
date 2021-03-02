const User = require('../models/user.mode')
const bycrypt = require('bcryptjs')
const jwt = require("jsonwebtoken");
var nodemailer = require("nodemailer");
const _=require('lodash')
const NodeRSA = require('node-rsa');
const key = new NodeRSA({b: 512});
async function signup(req,res,next) {
    const emailExist = await User.findOne({email: req.body.email})
  if(emailExist){
     res.status(400).json({"error":'Email already Exist'}) 
  }
    const salt = await bycrypt.genSalt(10);
  hashpassword = await bycrypt.hash(req.body.password, salt)
  const user =  new User({
    name: req.body.name,
    email: req.body.email,
    password:hashpassword
  })
  try{
    const userSignup = await user.save()
    const payload = {
      user: {
        id: userSignup.id
      }
    };
    jwt.sign(payload,"anystring",{expiresIn: 10000},async function(err, token)
    {
      if(err){
        res.send(err)
      }
      const encrypted = key.encrypt(token, 'base64');
      console.log('encrypted: ', encrypted);
      const decrypted = key.decrypt(encrypted, 'utf8');
      console.log('decrypted: ', decrypted);
      res.status(200).json({
        encrypted,
        userSignup
      })
    })
  } 
  catch(err){
    res.status(400).json({'error':err})
  }
}
async function login(req,res,next){
    const emailExist = await User.findOne({email: req.body.email})
    if(!emailExist){
      res.status(400).json({error:"Email not Found"})
    }
    const checkpassword = await bycrypt.compare(req.body.password, emailExist.password)
    if(!checkpassword){
      res.status(400).json({error:"Password mismatch"})
    }
    const token = jwt.sign({_id: emailExist.id},'anystring')
    const encrypted = key.encrypt(token, 'base64');
      console.log('encrypted: ', encrypted);
      const decrypted = key.decrypt(encrypted, 'utf8');
      console.log('decrypted: ', decrypted);
    res.header('auth-token',encrypted).json({'Token':encrypted})

  }
  
async function forgotpassword(req,res){
    email=req.body.email;
   const ans= await User.findOne({email});
   //console.log(ans)
        if(!ans)
        {
            return res.status(400).json({error:"User with this email does not exists"})

        }
        const token=jwt.sign({_id:ans._id},'anystring',{expiresIn:'20m',});
       const encrypted=await key.encrypt(token,'base64');
       console.log("This is encrypted token",encrypted);
        const ans1= await ans.updateOne({resetlink:token});
        console.log("this is ans1",ans1)
            if(!ans1)
            {
                return res.status(400).json({error:"password reset failed"});
            }
            else{
              console.log(
                "indside else"
              )
                let transporter = nodemailer.createTransport({
                    service: "gmail",
                    port: 25,
                    secure: false,
                    auth: {
                      user: "digi5technologies@gmail.com",
                      pass: "Digi5vgec@2021",
                    },
                    tls: {
                      rejectUnauthorized: false,
                    },
                  });
            
                 const ans2= await transporter.sendMail({
                    from: "digi5technologies@gmail.com",
                    to: req.body.email,
                    subject: "Reset Password link",
                    text: "Check out this link",
                    html:`<p>http://localhost:3000/reset/${encrypted}`,
                  }) 
                  if(!ans2)
                  {
                    res.status.send("Failed to Send Verification link");
                  }
                  else{
                    res.send("Mail sent Succesfully").status(200);
                  }
                  console.log(ans2)
            }
         
      }


async function resetpassword(req,res){
    let {resetlink,newpass}=req.body;
    const decrypted = await key.decrypt(resetlink, 'utf8');
    console.log('decrypted: ', decrypted);
    resetlink=decrypted;
    console.log("reset",resetlink)
    if(resetlink)
    {
        jwt.verify(resetlink,'anystring', async function(error,success){
          // console.log(error)
          // console.log(success)
            if(error)
            {
                console.log(error)
                 return res.status(400).json({error:"Verification1 failed"})
            }
            else{
               let ans= await User.findOne({resetlink})
                  //console.log(ans)
                    if(!ans)
                    {
                        return res.status(400).json({error:"Verification2 failed"})
                    }
                    const salt = await bycrypt.genSalt(10);
                    hashpassword = await bycrypt.hash(newpass, salt)
                    const obj={
                        password:hashpassword,
                        resetlink:''
                    }
                    try{
                    ans=_.extend(ans,obj);
                    }
                    catch(e)
                    {
                      console.log(e)
                    }
                    //console.log("after updation",ans)
                   const ans1=  await ans.save();
                   console.log(ans1)
                    if(!ans1)
                    {
                        return res.status(400).json({error:"Verification udpate failed"})
                    }
                    else{
                        return res.status(200).send(ans1);                        
                    }                
            }
            
        } )
    }else{
        return res.status(400).json({error:"Reset link doesn't exists"})
    }


    
}

module.exports = {
  signup,
  login,
  forgotpassword,
  resetpassword
}