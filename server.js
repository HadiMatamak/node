const express = require('express');
const axios = require('axios');
const cors = require('cors');
const morgan = require('morgan'); // Morgan is a middleware for logging HTTP requests

const app = express();

// Enable all CORS requests
app.use(cors());

// Use Morgan to log all incoming requests
app.use(morgan('combined'));

// Body parser middleware to parse JSON bodies and urlencoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Replace with your actual Converge credentials and API URLs
const merchantID = "2446101";
const merchantUserID = "8042061146web";
const merchantPIN = "MHL8T6CBZ1XXZ9SFGLZJ83WUQX6FJZVSFR3AB6FXXN70WE1G985PIZZDEROC683F";
const url = "https://api.convergepay.com/hosted-payments/transaction_token";

// Endpoint to create a session token
app.post('/create_token', async (req, res) => {
    const { ssl_first_name, ssl_last_name, ssl_amount } = req.body;

    // Logging the request body for debugging
    console.log('Received token creation request:', req.body);

    // Construct the POST data
    const postData = {
        ssl_merchant_id: merchantID,
        ssl_user_id: merchantUserID,
        ssl_pin: merchantPIN,
        ssl_transaction_type: 'ccsale',
        ssl_first_name: ssl_first_name,
        ssl_last_name: ssl_last_name,
        ssl_get_token: 'Y',
        ssl_add_token: 'Y',
        ssl_amount: ssl_amount
    };

    try {
        // Make the POST request to Converge
        const response = await axios.post(url, new URLSearchParams(postData), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        // Logging the response from Converge for debugging
        console.log('Token creation response:', response.data);

        // Send back the result
        res.json(response.data);
    } catch (error) {
        // Logging the error for debugging
        console.error('Error while creating token:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
