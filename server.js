//----------------user signup----------------------//
const User =  require('./userSchema');
const mongoose = require('mongoose');  
const dbUrl = `mongodb+srv://rajatvinay03:qwertyuiop@cluster0.uq3g28u.mongodb.net/?retryWrites=true&w=majority`;
const bcrypt = require('bcrypt');    
const jwt = require('jsonwebtoken');   
const express = require('express');
const { v4: uuidv4 } = require('uuid');

const connectionParams = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
};

mongoose
  .connect(dbUrl, connectionParams)
  .then(()=>{
    console.info("Connected to the DB");
  })
  .catch((err)=>{
    console.error("Error connecting to the DB", err);
  });

const app = express();
    
    app.use(express.json());
    
    app.post('/signup', async (req, res) => {
      try {
        const { email, mobileNumber, fullName, password } = req.body;
    
        // encrypt PII
        const encryptedEmail = encrypt(email);
        const encryptedMobileNumber = encrypt(mobileNumber);
        const encryptedFullName = encrypt(fullName);
    
        const user = new User({
          email: encryptedEmail,
          mobileNumber: encryptedMobileNumber,
          fullName: encryptedFullName,
          password,
        });
    
        await user.save();
    
        const token = await user.generateAuthToken();
    
        res.status(201).send({ user, token });
      } catch (error) {
        res.status(400).send(error);
      }
    });
    
    app.listen(3000, () => {
      console.log('Server is up on port 3000');
    });

    const crypto = require('crypto');
    
    function encrypt(text) {
      const algorithm = 'aes-256-cbc';
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(algorithm, key, iv);
    
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
    
      return `${iv.toString('hex')}:${key.toString('hex')}:${encrypted}`;
    }

    function decrypt(text) {
      const algorithm = 'aes-256-cbc';
      const [iv, key, encrypted] = text.split(':');
      const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
    
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
    
      return decrypted;
    }

    //----------------reset password------------------//
   
    // Sample secret key for JWT token
    const secretKey = 'mysecretkey';
    
    // Reset password endpoint
    app.post('/reset-password', (req, res) => {
      const { email, oldPassword, newPassword } = req.body;
    
      // Find the user by email
      const user = users.find(u => u.email === email);
    
      // If the user doesn't exist, return an error
      if (!user) {
        return res.status(400).json({ message: 'User not found' });
      }
    
      // Verify the old password
      const passwordMatch = bcrypt.compareSync(oldPassword, user.password);
    
      // If the old password doesn't match, return an error
      if (!passwordMatch) {
        return res.status(400).json({ message: 'Old password is incorrect' });
      }
    
      // Hash the new password
      const hashedPassword = bcrypt.hashSync(newPassword, 10);
    
      // Update the user's password
      user.password = hashedPassword;
    
      // Return a success message
      res.json({ message: 'Password reset successful' });
    });
    

// ------------------------login--------------------//

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  const user = users.find(u => u.email === email);

  // If the user doesn't exist, return an error
  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  // Verify the password
  const passwordMatch = bcrypt.compareSync(password, user.password);

  // If the password doesn't match, return an error
  if (!passwordMatch) {
    return res.status(400).json({ message: 'Invalid password' });
  }

  // Create a JWT token
  const tokenPayload = { id: user.id, email: user.email, mobileNumber: user.mobileNumber };
  const token = jwt.sign(tokenPayload, secretKey);

  // Return the token
  res.json({ token });
});

// -------------------------update user details-------------//

// Update user endpoint
app.put('/users/:id', (req, res) => {
  const { id } = req.params;
  const { fullName, mobileNumber } = req.body;

  // Find the user by ID
  const user = users.find(u => u.id === id);

  // If the user doesn't exist, return an error
  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  // Encrypt the new user details
  const encryptedFullName = encrypt(fullName);
  const encryptedMobileNumber = encrypt(mobileNumber);

  // Update the user details
  user.fullName = encryptedFullName;
  user.mobileNumber = encryptedMobileNumber;

  // Return the updated user details
  res.json({ id: user.id, email: user.email, fullName: decryptedFullName, mobileNumber: decryptedMobileNumber });
});

