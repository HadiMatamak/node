const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const winston = require('winston');
const crypto = require('crypto');
const util = require('util');
const sgMail = require('@sendgrid/mail');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const stripe = require('stripe')('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');
const randomBytesAsync = util.promisify(crypto.randomBytes);

// Hardcoded API key (strongly discouraged)
const SENDGRID_API_KEY = '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'; // Replace with your actual API key
sgMail.setApiKey(SENDGRID_API_KEY);

const app = express();


// Create a Winston logger for better debugging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => `${info.timestamp} [${info.level.toUpperCase()}]: ${info.message}`)
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

// Enable CORS for all routes and origins
app.use(cors());

app.use(bodyParser.json());

// Set up MySQL connection
const db = mysql.createConnection({
    host: "database-1.cubbmmbqwog3.us-east-2.rds.amazonaws.com",  // Replace with your RDS endpoint
    user: "admin",             // Replace with your RDS master username
    password: "bistro123",     // Replace with your RDS password
    database: "matadb"         // Replace with your database name
});

// Connect to the MySQL database
db.connect(error => {
    if (error) {
        logger.error('Error connecting to the MySQL server:', error.message);
        process.exit(1); // Exit the process with a failure code
    }
    logger.info('Connected to the MySQL server.');
});

// Define the storage engine for multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads'); // Set the directory where category images will be stored
    },
    filename: (req, file, cb) => {
        const extname = path.extname(file.originalname);
        const filename = `${Date.now()}${extname}`;
        cb(null, filename);
    },
});

const upload = multer({ storage });

// Create an "uploads" directory if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Serve files from the "uploads" directory
app.use('/uploads', express.static('uploads'));

let kitchenMessages = [];
let fohMessages = [];
let messageId = 0;

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  // Validate token against database and check for expiration
  db.query(
    'SELECT email FROM password_reset_requests WHERE token = ? AND expiration > NOW()',
    [token],
    (error, results) => {
      if (error) {
        console.error('Database error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
      }

      if (results.length > 0) {
        const email = results[0].email;

        // Update password in the user_signup table
        db.query(
          'UPDATE user_signup SET password = ? WHERE email = ?',
          [newPassword, email],
          (updateError) => {
            if (updateError) {
              console.error('Update error:', updateError);
              return res.status(500).json({ message: 'Error updating password.' });
            }

            // Invalidate the token by removing it
            db.query(
              'DELETE FROM password_reset_requests WHERE token = ?',
              [token],
              (deleteError) => {
                if (deleteError) {
                  console.error('Delete error:', deleteError);
                  return res.status(500).json({ message: 'Error invalidating token.' });
                }

                res.status(200).json({ message: 'Password updated successfully.' });
              }
            );
          }
        );
      } else {
        res.status(400).json({ message: 'Invalid or expired token.' });
      }
    }
  );
});
app.post('/request-password-reset', async (req, res) => {
  try {
    const email = req.body.email;
    const token = (await randomBytesAsync(20)).toString('hex');

    // Store token, email, and expiration time in the database
    db.query(
      'INSERT INTO password_reset_requests (email, token, expiration) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))',
      [email, token],
      (error, results) => {
        if (error) {
          console.error('Database error:', error);
          return res.status(500).json({ message: 'Internal Server Error' });
        }

        // Send email via SendGrid with token link
        const resetUrl = `https://matamak.s3.us-east-2.amazonaws.com/MatamakWeb/reseturpasswordsn10.html?token=${token}`;
        const msg = {
          to: email,
          from: 'memberships@matamak.ca', // Use the email verified with SendGrid
          subject: 'Password Reset Request',
          text: `To reset your password, please click the following link: ${resetUrl}`,
          html: `To reset your password, please click the following link: <a href="${resetUrl}">${resetUrl}</a>`,
        };

        sgMail.send(msg)
          .then(() => {
            res.status(200).json({ message: 'Reset link sent successfully.' });
          })
          .catch(sendGridError => {
            console.error('SendGrid error:', sendGridError);
            res.status(500).json({ message: 'Error sending reset link.' });
          });
      }
    );
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.' });
  }
});

app.get('/api/items/:itemID/extras', async (req, res) => {
    const { itemID } = req.params;

    try {
        const query = `
            SELECT extras.*, extrascategories.name as categoryName 
            FROM extras
            JOIN itemextras ON extras.extraID = itemextras.extraID
            JOIN extrascategories ON extras.categoryID = extrascategories.extrasCategoryID
            WHERE itemextras.itemID = ?
        `;
        const extras = await queryPromise(query, [itemID]);
        res.json({ success: true, extras });
    } catch (error) {
        logger.error(`Database error during extras fetching: ${error.message}`);
        res.status(500).json({ success: false, message: 'Server error during extras fetching.' });
    }
});

// Define an endpoint for uploading category images
app.post('/api/upload-category-image', upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No file uploaded' });
    }

    const { categoryName } = req.body;
    const imagePath = req.file.filename;

    const query = 'UPDATE categories SET image = ? WHERE name = ?';
    db.query(query, [imagePath, categoryName], (error) => {
        if (error) {
            logger.error('Database error:', error.message);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
        logger.info('Category image uploaded and saved to the database.');
        res.json({ success: true, message: 'Category image uploaded successfully', imagePath });
    });
});


app.get('/api/get-category-image/:categoryName', (req, res) => {
    const { categoryName } = req.params;

    // Retrieve the image path from the database for the specified category
    const query = 'SELECT image FROM categories WHERE name = ?';
    db.query(query, [categoryName], (error, results) => {
        if (error) {
            logger.error('Database error:', error.message);
            return res.status(500).json({ success: false, message: 'Server error' });
        } 
        
        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'Category not found' });
        }

        const imagePath = results[0].image;

        if (!imagePath) {
            logger.error('Image path is not defined for category:', categoryName);
            return res.status(500).json({ success: false, message: 'Image path is not defined for the category' });
        }

        logger.info('Category image retrieved successfully.');
        res.json({ success: true, message: 'Category image retrieved successfully', imagePath });
    });
});



// Endpoint to add a new category
	app.post('/api/categories', (req, res) => {
		const { name, image } = req.body;
		const query = 'INSERT INTO categories (name, image) VALUES (?, ?)';

		db.query(query, [name, image], (error, results) => {
			if (error) {
				logger.error('Database error:', error.message);
				res.status(500).json({ success: false, message: 'Server error' });
			} else {
				logger.info('Successfully added a new category.');
				res.json({ success: true, categoryId: results.insertId });
			}
		});
	});

	// Endpoint to retrieve categories
	app.get('/api/categories', (req, res) => {
		const query = 'SELECT * FROM categories';

		db.query(query, (error, results) => {
			if (error) {
				logger.error('Database error:', error.message);
				res.status(500).json({ success: false, message: 'Server error' });
			} else {
				logger.info('Retrieved categories.');
				res.json({ success: true, categories: results });
			}
		});
	});



// Endpoint to add an item
app.post('/api/items', (req, res) => {
    logger.info('Received request to add a new item.');
    const { categoryName, name, price, baseFeePercentage, hstPercentage } = req.body;

    // Validation
    if (typeof categoryName !== "string" || categoryName.trim() === "") {
        logger.warn('Validation failed: Invalid categoryName.');
        return res.status(400).json({ success: false, message: 'Invalid categoryName.' });
    }
    if (typeof name !== "string" || name.trim() === "") {
        logger.warn('Validation failed: Invalid name.');
        return res.status(400).json({ success: false, message: 'Invalid name.' });
    }
    if (isNaN(price)) {
        logger.warn('Validation failed: Invalid price.');
        return res.status(400).json({ success: false, message: 'Invalid price.' });
    }
    if (isNaN(baseFeePercentage)) {
        logger.warn('Validation failed: Invalid baseFeePercentage.');
        return res.status(400).json({ success: false, message: 'Invalid baseFeePercentage.' });
    }
    if (isNaN(hstPercentage)) {
        logger.warn('Validation failed: Invalid hstPercentage.');
        return res.status(400).json({ success: false, message: 'Invalid hstPercentage.' });
    }

    // Database operation to insert into Items table
    const query = `
        INSERT INTO items (categoryID, name, price, baseFeePercentage, hstPercentage) 
        VALUES ((SELECT categoryID FROM categories WHERE name = ? LIMIT 1), ?, ?, ?, ?)
    `;

    db.query(query, [categoryName, name, price, baseFeePercentage, hstPercentage], (error, results) => {
        if (error) {
            logger.error(`Database error during item insertion: ${error.message}`);
            res.status(500).json({ success: false, message: 'Server error during item insertion.' });
        } else {
            logger.info(`Successfully inserted item with ID ${results.insertId}.`);
            res.json({ success: true, itemID: results.insertId });
        }
    });
});
app.get('/api/items', (req, res) => {
    const { categoryName } = req.query;

    let query = `
        SELECT 
            items.*,
            extras.extraID,
            extras.name AS extraName, 
            extras.price AS extraPrice, 
            extras.qty AS extraQty,
            extrascategories.name AS extraCategory
        FROM items
        LEFT JOIN itemextras ON items.itemID = itemextras.itemID
        LEFT JOIN extras ON itemextras.extraID = extras.extraID
        LEFT JOIN extrascategories ON extras.categoryID = extrascategories.extrasCategoryID
    `;

    const queryParams = [];

    if (categoryName) {
        query += ` WHERE items.categoryID = (SELECT categoryID FROM categories WHERE name = ? LIMIT 1)`;
        queryParams.push(categoryName);
    }

    db.query(query, queryParams, (error, results) => {
        if (error) {
            logger.error(`Database error fetching items: ${error.message}`);
            return res.status(500).json({ success: false, message: 'Server error fetching items.' });
        }

        const itemsMap = {};
        results.forEach(row => {
            if (!itemsMap[row.itemID]) {
                itemsMap[row.itemID] = {
                    itemID: row.itemID,
                    name: row.name,
                    price: row.price,
                    baseFeePercentage: row.baseFeePercentage,
                    hstPercentage: row.hstPercentage,
                    extras: []
                };
            }

            if (row.extraID) {
                itemsMap[row.itemID].extras.push({
                    extraID: row.extraID,
                    name: row.extraName,
                    price: row.extraPrice,
                    qty: row.extraQty,
                    category: row.extraCategory
                });
            }
        });

        const items = Object.values(itemsMap);
        res.json({ success: true, items });
    });
});


app.post('/api/extras', (req, res) => {
    const { name, price, qty, category } = req.body;

    logger.info(`Attempting to insert extra with details: Name: ${name}, Price: ${price}, Qty: ${qty}, Category: ${category}`);

    // Fetch the categoryID from the extrascategories table based on the category name
    db.query('SELECT extrasCategoryID FROM extrascategories WHERE name = ?', [category], (categoryError, categories) => {
        if (categoryError) {
            logger.error(`Database error while querying for extrasCategoryID: ${categoryError.message}`);
            return res.status(500).json({ success: false, message: 'Server error while querying for extrasCategoryID.' });
        }

        if (categories.length === 0) {
            // If the category does not exist, insert it first
            db.query('INSERT INTO extrascategories (name) VALUES (?)', [category], (insertCategoryError, insertCategoryResults) => {
                if (insertCategoryError) {
                    logger.error(`Database error while inserting extras category: ${insertCategoryError.message}`);
                    return res.status(500).json({ success: false, message: 'Server error while inserting extras category.' });
                }
                // Proceed with inserting the extra
                insertExtra(insertCategoryResults.insertId);
            });
        } else {
            const categoryId = categories[0].extrasCategoryID;
            insertExtra(categoryId);
        }
    });

    function insertExtra(categoryId) {
        const query = 'INSERT INTO extras (name, price, qty, categoryID) VALUES (?, ?, ?, ?)';
        db.query(query, [name, price, qty, categoryId], (error, results) => {
            if (error) {
                logger.error(`Database error during extra insertion: ${error.message}`);
                return res.status(500).json({ success: false, message: 'Server error during extra insertion.' });
            }
            logger.info(`Successfully inserted extra with ID ${results.insertId}.`);
            res.json({ success: true, extraID: results.insertId });
        });
    }
});

function queryPromise(query, params) {
    return new Promise((resolve, reject) => {
        db.query(query, params, (error, results) => {
            if (error) {
                return reject(error);
            }
            resolve(results);
        });
    });
}

// Endpoint to delete a category by name
// Endpoint to delete a category by name
app.delete('/api/categories/:categoryName', async (req, res) => {
  const categoryName = req.params.categoryName;

  // Start a transaction to ensure atomicity
  db.beginTransaction(async error => {
    if (error) {
      logger.error(`Transaction error: ${error.message}`);
      return res.status(500).json({ success: false, message: 'Server error starting transaction.' });
    }

    try {
      // Step 1: Delete associated item-extras
      const deleteItemExtrasQuery = `
        DELETE itemextras FROM itemextras 
        INNER JOIN items ON itemextras.itemID = items.itemID 
        INNER JOIN categories ON items.categoryID = categories.categoryID 
        WHERE categories.name = ?`;
      await queryPromise(deleteItemExtrasQuery, [categoryName]);

      // Step 2: Delete associated items
      const deleteItemsQuery = `
        DELETE FROM items 
        WHERE categoryID = (SELECT categoryID FROM categories WHERE name = ? LIMIT 1)`;
      await queryPromise(deleteItemsQuery, [categoryName]);

      // Step 3: Delete the category
      const deleteCategoryQuery = 'DELETE FROM categories WHERE name = ?';
      await queryPromise(deleteCategoryQuery, [categoryName]);

      // Commit the transaction
      db.commit(error => {
        if (error) {
          throw error;  // This will be caught by the catch block below
        }

        logger.info('Successfully deleted a category and associated items and item-extras.');
        res.json({ success: true });
      });
    } catch (error) {
      // Rollback the transaction in case of any errors
      db.rollback(() => {
        logger.error(`Database error during category deletion: ${error.message}`);
        res.status(500).json({ success: false, message: 'Server error during category deletion.' });
      });
    }
  });
});

// Endpoint to associate an extra with an item
app.post('/api/item-extras', (req, res) => {
    const { itemID, extraID } = req.body;

    if (isNaN(itemID)) {
        logger.warn('Validation failed: Invalid itemID.');
        return res.status(400).json({ success: false, message: 'Invalid itemID.' });
    }
    if (isNaN(extraID)) {
        logger.warn('Validation failed: Invalid extraID.');
        return res.status(400).json({ success: false, message: 'Invalid extraID.' });
    }

    const query = 'INSERT INTO itemextras (itemID, extraID) VALUES (?, ?)';

    db.query(query, [itemID, extraID], (error, results) => {
        if (error) {
            logger.error(`Database error during item-extra association: ${error.message}`);
            res.status(500).json({ success: false, message: 'Server error during item-extra association.' });
        } else {
            logger.info('Successfully associated an extra with an item.');
            res.json({ success: true });
        }
    });
});
async function getCategoryIdByName(categoryName) {
  const query = 'SELECT categoryID FROM categories WHERE name = ?';
  const results = await queryPromise(query, [categoryName]);
  if (results.length > 0) {
    return results[0].categoryID;
  } else {
    throw new Error(`Category not found: ${categoryName}`);
  }
}

// Endpoint to delete an item
app.delete('/api/items/:categoryName/:itemName', async (req, res) => {
  const { categoryName, itemName } = req.params;

  try {
    const categoryId = await getCategoryIdByName(categoryName);
    // Delete associated extras first
    await queryPromise('DELETE FROM itemextras WHERE itemID IN (SELECT itemID FROM items WHERE name = ? AND categoryID = ?)', [itemName, categoryId]);
    // Then, delete the item
    await queryPromise('DELETE FROM items WHERE name = ? AND categoryID = ?', [itemName, categoryId]);
    res.json({ success: true, message: 'Item deleted successfully' });
  } catch (error) {
    logger.error(`Database error during item deletion: ${error.message}`);
    res.status(500).json({ success: false, message: 'Server error during item deletion.' });
  }
});
app.get('/api/menu', async (req, res) => {
    try {
        const categoriesQuery = 'SELECT * FROM categories';
        const categories = await queryPromise(categoriesQuery);

        const itemsQuery = 'SELECT * FROM items';
        const items = await queryPromise(itemsQuery);

        const extrasQuery = 'SELECT * FROM extras';
        const extras = await queryPromise(extrasQuery);

        res.json({ success: true, data: { categories, items, extras } });
    } catch (error) {
        logger.error(`Database error during menu fetching: ${error.message}`);
        res.status(500).json({ success: false, message: 'Server error during menu fetching.' });
    }
});

app.post('/create-payment-intent', async (req, res) => {
	
    try {
        console.log("Received request with body:", req.body);
        
        let { totalAmount } = req.body;
        
        // Convert totalAmount to cents and ensure it's an integer
        totalAmount = Math.round(totalAmount * 100);

        // Ensure totalAmount is a positive integer
        if (!totalAmount || typeof totalAmount !== 'number' || totalAmount <= 0) {
            throw new Error("Invalid totalAmount in request body");
        }

        const paymentIntent = await stripe.paymentIntents.create({
            amount: totalAmount, // now in cents
            currency: 'cad'
        });

        console.log("Created PaymentIntent:", paymentIntent);
        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (err) {
        console.error("Error occurred:", err);
        res.status(500).json({ error: err.message });
    }
});
app.post('/create-subscription', async (req, res) => {
    try {
        const { email, paymentMethodId } = req.body;

        if (!email || !paymentMethodId) {
            throw new Error("Email and paymentMethodId are required");
        }

        // Create a new customer object
        const customer = await stripe.customers.create({
            email: email,
            payment_method: paymentMethodId,
            invoice_settings: {
                default_payment_method: paymentMethodId,
            },
        });

        // Create the subscription
        const subscription = await stripe.subscriptions.create({
            customer: customer.id,
            items: [{ price: 'price_1NvjKHBYsXuC75xW5ontx0yr' }], // replace 'price_ID' with the ID of the price object you created in the Stripe Dashboard
            expand: ['latest_invoice.payment_intent'],
        });

        res.json({
            subscriptionId: subscription.id,
            clientSecret: subscription.latest_invoice.payment_intent.client_secret,
        });
    } catch (err) {
        console.error("Error occurred:", err);
        res.status(500).json({ error: err.message });
    }
});
// Endpoint to retrieve items






app.post('/signin', (req, res) => {
    // Authenticate user
    const { email, password } = req.body;
    const authQuery = 'SELECT id, password FROM user_signup WHERE email = ?';
    db.query(authQuery, [email], (err, result) => {
        if (err) {
            console.error('Error during signin:', err);
            return res.status(500).send('Server error');
        }

        if (!result.length) {
            return res.status(401).send('Email not found');
        }

        if (result[0].password !== password) {
            return res.status(401).send('Incorrect password');
        }
		

        // Fetch associated random letters for the user
        const fetchRandomLettersQuery = 'SELECT randomLetters FROM qr_codes WHERE userId = ?';
        db.query(fetchRandomLettersQuery, [result[0].id], (err, qrResult) => {
            if (err) {
                console.error('Error fetching random letters:', err);
                return res.status(500).send('Could not fetch random letters');
            }

            if (!qrResult.length) {
                return res.status(404).send('Random letters data not found');
            }

            res.status(200).send({ message: 'Signin successful!', randomLetters: qrResult[0].randomLetters });
        });
    });
});


app.post('/signup', async (req, res) => {
  const { firstName, phoneNumber, email, password } = req.body;

  // Generate a random 5-letter string
  const randomLetters = Array.from({ length: 5 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join('');

  // SQL query to insert new user into the database
  const query = 'INSERT INTO user_signup (firstName, phoneNumber, email, password) VALUES (?, ?, ?, ?)';

  // Execute the query
  db.query(query, [firstName, phoneNumber, email, password], (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).send('Server error');
      return;
    }

    // Insert randomLetters into qr_codes table
    const userId = result.insertId;
    const insertRandomLettersQuery = 'INSERT INTO qr_codes (userId, randomLetters) VALUES (?, ?)';
    db.query(insertRandomLettersQuery, [userId, randomLetters], (err, qrResult) => {
      if (err) {
        console.error(err);
        res.status(500).send('Could not save random letters');
        return;
      }
      res.status(200).send({ message: 'Signup successful!', randomLetters });
    });
  });
});
// Define the generateRedeemCode function
function generateRedeemCode() {
  // Example implementation that generates a random alphanumeric string of length 8
  let code = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const charactersLength = characters.length;
  for (let i = 0; i < 8; i++) {
    code += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return code;
}
 // Array to store messages

// Endpoint to receive messages from the kitchen
function addMessage(targetArray, content, sender) {
  targetArray.push({ id: messageId++, content: content, sender: sender });
  // Keep only the latest 50 messages
  if (targetArray.length > 50) {
    targetArray.shift(); // Remove the oldest message
  }
}

app.post('/message/kitchen', (req, res) => {
  console.log('Kitchen message received:', req.body.message);
  addMessage(kitchenMessages, req.body.message, 'Manager'); // Note the 'Manager' sender here
  res.status(200).send('Kitchen message received');
});

app.post('/message/foh', (req, res) => {
  console.log('Manager message received:', req.body.message);
  // Label the sender as 'Manager' when storing the message
  addMessage(fohMessages, req.body.message, 'Manager');
  res.status(200).send('Manager message received');
});


// Endpoint to get messages for the kitchen
app.get('/messages/kitchen', (req, res) => {
  res.status(200).json(kitchenMessages);
});

// Endpoint to get messages for the FOH
app.get('/messages/foh', (req, res) => {
  const lastMessageId = req.query.since_id ? parseInt(req.query.since_id) : 0;
  const newMessages = fohMessages.filter(message => message.id > lastMessageId);
  res.status(200).json(newMessages);
});


// Endpoint to acknowledge the receipt of messages
app.post('/messages/acknowledge', (req, res) => {
  const { lastMessageId } = req.body;
  // Filter out messages that have been acknowledged
  kitchenMessages = kitchenMessages.filter(message => message.id > lastMessageId);
  fohMessages = fohMessages.filter(message => message.id > lastMessageId);
  res.status(200).send('Messages acknowledged');
});

app.post('/fsignup', async (req, res) => {
  const { firstName, phoneNumber, email, password } = req.body;

  // Generate a random 5-letter string for QR code
  const randomLetters = Array.from({ length: 5 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join('');

  // Generate a 9-digit random number for QR code
  const randomNumber = Math.floor(100000000 + Math.random() * 900000000);

  // Generate a random redeem code
  const redeemCode = generateRedeemCode(); // Implement this function to generate a redeem code

  // SQL query to insert new user into the database
  const userQuery = 'INSERT INTO user_signup (firstName, phoneNumber, email, password) VALUES (?, ?, ?, ?)';

  // Execute the query to insert user
  db.query(userQuery, [firstName, phoneNumber, email, password], (err, userResult) => {
    if (err) {
      console.error(err);
      res.status(500).send('Server error');
      return;
    }

    const userId = userResult.insertId;

    // Insert randomLetters and randomNumber into qr_codes table
    const qrCodeQuery = 'INSERT INTO qr_codes (userId, randomLetters, randomNumber) VALUES (?, ?, ?)';
    db.query(qrCodeQuery, [userId, randomLetters, randomNumber], (err, qrResult) => {
      if (err) {
        console.error(err);
        res.status(500).send('Could not save QR code');
        return;
      }

      // Insert redeemCode into redeem_codes table
      const redeemCodeQuery = 'INSERT INTO redeem_codes (userId, code) VALUES (?, ?)';
      db.query(redeemCodeQuery, [userId, redeemCode], (err, redeemResult) => {
        if (err) {
          console.error(err);
          res.status(500).send('Could not save redeem code');
          return;
        }
        res.status(200).send({ message: 'Signup successful!', randomLetters, randomNumber, redeemCode });
      });
    });
  });
});

app.post('/signin', (req, res) => {
  const { email, password, redeemCode } = req.body;

  if (redeemCode) {
    // Sign in with redeem code
    const redeemQuery = 'SELECT userId FROM redeem_codes WHERE code = ? AND used = FALSE';
    db.query(redeemQuery, [redeemCode], (err, redeemResults) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Server error');
      }

      if (redeemResults.length === 0) {
        return res.status(401).send('Invalid or already used redeem code');
      }

      const { userId } = redeemResults[0];
      res.status(200).send({ message: 'Signin successful!' });

      // Optionally, mark the redeem code as used
      const updateQuery = 'UPDATE redeem_codes SET used = TRUE WHERE code = ?';
      db.query(updateQuery, [redeemCode], (err, updateResults) => {
        if (err) {
          console.error('Error updating redeem code status:', err);
        }
      });
    });

  } else if (email && password) {
    // Sign in with email and password
    const query = 'SELECT id, password FROM user_signup WHERE email = ?';
    db.query(query, [email], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Server error');
      }

      if (result.length === 0) {
        return res.status(401).send('Email not found');
      }

      const storedPassword = result[0].password;
      if (storedPassword === password) {
        res.status(200).send({ message: 'Signin successful!' });
      } else {
        res.status(401).send('Incorrect password');
      }
    });

  } else {
    res.status(400).send('Email and password or redeem code required');
  }
});

app.get('/getUserByRandomLetters/:randomLetters', (req, res) => {
    const { randomLetters } = req.params;

    // Query the database to get user details based on random letters
    const query = `
      SELECT user_signup.firstName, user_signup.phoneNumber, user_signup.email 
      FROM user_signup 
      JOIN qr_codes ON user_signup.id = qr_codes.userId
      WHERE qr_codes.randomLetters = ?`;

    db.query(query, [randomLetters], (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).send('Server error');
            return;
        }

        if (result.length === 0) {
            res.status(404).send('User not found for given random letters');
            return;
        }

        const userDetails = result[0];
        res.status(200).send(userDetails);
    });
});
app.post('/get_order_history', (req, res) => {
    const email = req.body.email;

    const query = `
      SELECT * FROM new_receipts
      WHERE email = ?
    `;

    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Error fetching order history:', err);
            return res.status(500).send('Server error');
        }

        // Ensure receiptData is parsed into an object
        results.forEach(result => {
            if (result.receiptData && typeof result.receiptData === 'string') {
                try {
                    result.receiptData = JSON.parse(result.receiptData);
                } catch (e) {
                    console.error("Error parsing JSON for receiptData:", e);
                }
            }
        });

        res.status(200).send(results);
    });
});

app.delete('/api/categories/:categoryName/items/:itemName/extras/:extraName', async (req, res) => {
  const { categoryName, itemName, extraName } = req.params;

  logger.info(`Received request to delete association between item '${itemName}' in category '${categoryName}' and extra '${extraName}'`);

  const deleteQuery = `
    DELETE itemextras FROM itemextras
    INNER JOIN items ON itemextras.itemID = items.itemID
    INNER JOIN extras ON itemextras.extraID = extras.extraID
    INNER JOIN categories ON items.categoryID = categories.categoryID
    WHERE categories.name = ? AND items.name = ? AND extras.name = ?
  `;

  try {
    logger.info('Executing delete query...');
    const results = await queryPromise(deleteQuery, [categoryName, itemName, extraName]);
    logger.info('Delete query executed successfully.');

    if (results.affectedRows === 0) {
      logger.warn('No association found between the specified item, category, and extra. No rows affected.');
      return res.status(404).json({ success: false, message: 'Association between item, category, and extra not found' });
    }

    logger.info('Association between item, category, and extra deleted successfully.');
    res.json({ success: true, message: 'Association between item, category, and extra deleted successfully' });
  } catch (error) {
    logger.error('Database error:', error.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



app.post('/send_receipt', (req, res) => {
    const { email, receiptData } = req.body;
    const order_id = receiptData.orderID;
    const items = receiptData.items;

    if (!order_id || !items) {
        return res.status(400).send('Invalid receipt data');
    }

    // For simplicity, let's assume you want to store the first item's name and its extras.
    // You might want to adjust this if you have multiple items or a different logic.
    const burger_type = items[0].name;
    const extras = items[0].extras;

    const subtotal = receiptData.subtotal;
    const hst = receiptData.hst;
    const total_with_tax = receiptData.total;

    const query = `
        INSERT INTO new_receipts (
            email, order_id, burger_type, extras, item_total, receipt_content, subtotal, hst, total_with_tax, date_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
        email,
        order_id,
        burger_type,
        JSON.stringify(extras),
        items[0].price,  // item_total for simplicity from the first item.
        JSON.stringify(items),
        subtotal,
        hst,
        total_with_tax,
        new Date(receiptData.dateTime)  // Convert string date to Date object
    ];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('Error inserting receipt into the database:', err);
            return res.status(500).send('Server error');
        }
        console.log("Receipt successfully inserted into the database.");
        res.status(200).send('Receipt received and stored successfully');
    });
});


app.get('/get_receipt_data', (req, res) => {
  // Filter to get only new, unfetched receipts
  const new_receipts = receipts.filter(r => !r.fetched);

  // Mark these receipts as fetched
  new_receipts.forEach(receipt => {
    receipt.fetched = true;
  });

  res.json({ kitchen_receipt: new_receipts });
});

const updateQRCodesForAllUsers = () => {
    const fetchUserIdsQuery = 'SELECT id FROM user_signup';
    db.query(fetchUserIdsQuery, [], (err, results) => {
        if (err) {
            console.error('Error fetching user IDs:', err);
            return;
        }

        results.forEach(row => {
            const userId = row.id;
            const randomLetters = Array.from({ length: 5 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join('');
            const expirationTime = new Date(Date.now() + 10 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ');

            const updateQRCodeQuery = 'UPDATE qr_codes SET randomLetters = ?, expiration_time = ? WHERE userId = ?';
            db.query(updateQRCodeQuery, [randomLetters, expirationTime, userId], (err) => {
                if (err) {
                    console.error('Error updating random letters for user:', userId, err);
                }
            });
        });
    });
};

setInterval(updateQRCodesForAllUsers, 10 * 60 * 1000);  // 10 minutes in milliseconds

// Start the server
const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});