const mongoose = require('mongoose');  //for database connection and uses
    const bcrypt = require('bcrypt');    //for password hashing
    const jwt = require('jsonwebtoken');   //session,login
    const { v4: uuidv4 } = require('uuid'); //public api key
    
    const userSchema = new mongoose.Schema({
      email: {
        type: String,
        required: true,
        unique: true,
      },
      mobileNumber: {
        type: String,
        required: true,
      },
      fullName: {
        type: String,
        required: true,
      },
      password: {
        type: String,
        required: true,
      },
      tokens: [
        {
          token: {
            type: String,
            required: true,
          },
        },
      ],
    });
    
    userSchema.pre('save', async function (next) {
      const user = this;
    
      if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
      }
      next();
    });
    
    userSchema.methods.generateAuthToken = async function () {
      const user = this;
    
      const token = jwt.sign(
        { _id: user._id.toString(), email: user.email, mobileNumber: user.mobileNumber },
        process.env.JWT_SECRET,
      );
    
      user.tokens = user.tokens.concat({ token });
      await user.save();
    
      return token;
    };
    
    const User = mongoose.model('User', userSchema);
    
    module.exports = User;